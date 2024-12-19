/*
 * Copyright 2024 RingNet
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::{Bytes, BytesMut};
use openssl::derive::Deriver;
use openssl::pkey::{Id, PKey, Private};
use parking_lot::Mutex;
use tokio::task::JoinHandle;
use tokio::time::interval;

use crate::crypto;
use crate::error::Error;
use ringlink_identity::{DeviceID, Identity, PublicIdentity};
use ringlink_p2p::{Agent, Candidate, P2PManager};
use ringlink_protocol::body::{KeyExchange, KEY_EXCHANGE_REPLY, KEY_EXCHANGE_REQUEST};
use ringlink_protocol::{Packet, PacketBody};
use ringlink_transport::Transport;

#[derive(Default)]
struct Kex {
    handle: Option<JoinHandle<()>>,
}

/// Peer on RingLink
pub struct Peer<T> {
    /// peer device id
    id: DeviceID,
    identity: Identity,
    /// peer public identity
    peer_identity: PublicIdentity,
    /// derived secret key to encrypt and decrypt data
    psk: ArcSwap<Vec<u8>>,
    /// random local encrypt key
    encrypt_key: PKey<Private>,
    kex: Mutex<Kex>,
    agent: Arc<Agent<T>>,
}

impl<T> Peer<T> {
    pub(crate) async fn new(
        identity: &Identity,
        peer_identity: PublicIdentity,
        p2p: &P2PManager<T>,
    ) -> Result<Peer<T>, Error>
    where
        T: Transport + Sync + Send + 'static,
    {
        // init psk with zero
        let psk = vec![0u8; 32];

        let peer = Peer {
            id: peer_identity.id(),
            identity: identity.clone(),
            peer_identity: peer_identity.clone(),
            psk: ArcSwap::from_pointee(psk),
            encrypt_key: PKey::generate_x25519()?,
            kex: Default::default(),
            agent: p2p.add_peer(peer_identity).await,
        };
        peer.start_kex()?;

        Ok(peer)
    }

    /// Get peer device id
    pub fn id(&self) -> DeviceID {
        self.id
    }

    /// Get peer public identity
    pub fn identity(&self) -> &PublicIdentity {
        &self.peer_identity
    }

    pub(crate) fn encrypt(&self, data: &[u8]) -> Result<(BytesMut, [u8; 12]), Error> {
        let psk = self.psk.load();
        crypto::encrypt(&*psk, data)
    }

    pub(crate) fn decrypt(&self, data: &[u8], iv: &[u8]) -> Result<BytesMut, Error> {
        let psk = self.psk.load();
        crypto::decrypt(&*psk, data, iv)
    }

    /// Set psk for peer
    ///
    /// PSK is used to encrypt and decrypt data
    pub fn set_psk(&self, psk: impl AsRef<[u8]>) {
        let psk = Arc::new(psk.as_ref().to_vec());
        self.psk.store(psk.clone());
    }

    fn verify_kex(&self, kex: &KeyExchange) -> Result<bool, Error> {
        // verify signature
        Ok(self.peer_identity.verify(&kex.public_key, &kex.signature)?)
    }

    pub async fn set_candidates(&self, candidates: HashSet<Candidate>) {
        self.agent.set_remote_candidate(candidates).await;
    }

    /// Send data to peer directly
    pub async fn send_direct(&self, data: Bytes) -> Result<usize, Error>
    where
        T: Transport + Sync + Send + 'static,
    {
        let n = self.agent.send(data).await?;
        Ok(n)
    }

    /// Get underlying agent
    pub fn agent(&self) -> &Agent<T> {
        &self.agent
    }

    fn make_kex(&self) -> Result<KeyExchange, Error> {
        let public_key = self.encrypt_key.raw_public_key()?;
        let signature = self.identity.sign(&public_key)?;

        Ok(KeyExchange {
            typ: KEY_EXCHANGE_REQUEST,
            public_key: Bytes::from(public_key),
            signature: Bytes::from(signature),
        })
    }

    fn start_kex(&self) -> Result<(), Error>
    where
        T: Transport + Sync + Send + 'static,
    {
        let kex = self.make_kex()?;

        let fut = trans_kex(
            self.identity.clone(),
            self.peer_identity.clone(),
            self.agent.clone(),
            kex,
        );
        let handle = tokio::spawn(fut);

        let mut kex = self.kex.lock();
        // cancel current running kex
        if let Some(handle) = kex.handle.take() {
            handle.abort();
        }

        kex.handle = Some(handle);
        Ok(())
    }

    async fn process_kex_request(&self, kex: KeyExchange) -> Result<(), Error>
    where
        T: Transport + Sync + Send + 'static,
    {
        if !self.verify_kex(&kex)? {
            return Err(Error::InvalidData);
        }

        // derive psk
        let peer_key = PKey::public_key_from_raw_bytes(&kex.public_key, Id::X25519)?;
        let mut deriver = Deriver::new(&self.encrypt_key)?;
        deriver.set_peer(&peer_key)?;
        let psk = deriver.derive_to_vec()?;

        // replace current psk
        self.psk.store(Arc::new(psk));

        // reply with our public key
        let self_public_key = self.encrypt_key.raw_public_key()?;
        let signature = self.identity.sign(&self_public_key)?;

        let reply_kex = KeyExchange {
            typ: KEY_EXCHANGE_REPLY,
            public_key: Bytes::from(self_public_key),
            signature: Bytes::from(signature),
        };
        let pkt = Packet::new(
            self.identity.id(),
            self.peer_identity.id(),
            PacketBody::KeyExchange(reply_kex),
        );
        let pkt = pkt.encode_into_bytes();

        self.agent.send(pkt.freeze()).await?;

        Ok(())
    }

    async fn process_kex_response(&self, kex: KeyExchange) -> Result<(), Error> {
        if !self.verify_kex(&kex)? {
            return Err(Error::InvalidData);
        }

        // derive psk
        let peer_key = PKey::public_key_from_raw_bytes(&kex.public_key, Id::X25519)?;
        let mut deriver = Deriver::new(&self.encrypt_key)?;
        deriver.set_peer(&peer_key)?;
        let psk = deriver.derive_to_vec()?;

        // replace current psk
        self.psk.store(Arc::new(psk));

        // cancel kex task only if got response
        let mut state = self.kex.lock();
        if let Some(handle) = state.handle.take() {
            handle.abort();
        }

        Ok(())
    }

    pub(crate) async fn process_kex(&self, kex: KeyExchange) -> Result<(), Error>
    where
        T: Transport + Sync + Send + 'static,
    {
        match kex.typ {
            KEY_EXCHANGE_REQUEST => self.process_kex_request(kex).await?,
            KEY_EXCHANGE_REPLY => self.process_kex_response(kex).await?,
            _ => return Err(Error::InvalidData),
        }
        Ok(())
    }
}

/// transmit key exchange until got response or stop
async fn trans_kex<T>(
    identity: Identity,
    public_identity: PublicIdentity,
    agent: Arc<Agent<T>>,
    key_exchange: KeyExchange,
) where
    T: Transport + Send + Sync + 'static,
{
    let mut tick = interval(Duration::from_secs(1));
    loop {
        tick.tick().await;

        let pkt = Packet::new(
            identity.id(),
            public_identity.id(),
            PacketBody::KeyExchange(key_exchange.clone()),
        );
        let pkt = pkt.encode_into_bytes();
        _ = agent.send(pkt.freeze()).await;
    }
}
