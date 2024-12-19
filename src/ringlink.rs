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

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, Bytes, BytesMut};
use tokio::task::{unconstrained, JoinHandle};
use tracing::{error, trace};

use crate::codec::DataKind;
use crate::error::{Error, Result};
use crate::network::Network;
use crate::topology::Topology;
use ringlink_identity::{DeviceID, Identity};
use ringlink_protocol::body::Binding;
use ringlink_protocol::body::Data;
use ringlink_protocol::{NetId, Packet, PacketBody, PacketMessage};
use ringlink_transport::Transport;

struct Inner<T> {
    identity: Identity,
    topology: Topology<T>,
    networks: papaya::HashMap<NetId, Network<T>>,
    transport: T,
}

/// The RingLink instance
pub struct RingLink<T> {
    inner: Arc<Inner<T>>,
    tasks: Vec<JoinHandle<()>>,
}

impl<T> RingLink<T>
where
    T: Transport + 'static,
{
    /// Create a new RingLink instance
    ///
    /// Enable user manually configured RingLink topology
    ///
    /// # Arguments
    /// * `identity` - [Identity]
    /// * `transport` - [Transport]
    /// * `topology` - [Topology]
    pub fn new(identity: Identity, transport: T, topology: Topology<T>) -> Self {
        let inner = Arc::new(Inner {
            identity,
            topology,
            networks: Default::default(),
            transport,
        });

        let mut tasks = Vec::new();
        {
            let inner = inner.clone();
            let handle = tokio::spawn(unconstrained(async move { inner.run().await }));
            tasks.push(handle);
        }

        RingLink { inner, tasks }
    }

    /// Get underlying [Topology]
    pub fn topology(&self) -> &Topology<T> {
        &self.inner.topology
    }

    /// Get underlying [Identity]
    pub fn identity(&self) -> &Identity {
        &self.inner.identity
    }

    /// Get underlying [Transport]
    pub fn transport(&self) -> &T {
        &self.inner.transport
    }

    /// Connect to a network
    ///
    /// # Arguments
    /// * `id` - network id
    pub fn connect(&self, id: NetId) -> Result<Network<T>> {
        let network =
            Network::connect(id, self.inner.identity.clone(), self.inner.topology.clone())?;

        let networks = self.inner.networks.pin();
        networks.insert(id, network.clone());

        Ok(network)
    }

    /// Disconnect from a network
    pub fn disconnect(&self, id: NetId) -> Option<Network<T>> {
        let networks = self.inner.networks.pin();
        let old = networks.remove(&id);

        old.cloned()
    }

    /// Stop the RingLink instance
    pub fn stop(&self) {
        self.inner.topology.stop();
        for handle in self.tasks.iter() {
            handle.abort();
        }
    }
}

impl<T> Inner<T>
where
    T: Transport + 'static,
{
    /// Process data packet
    async fn process_data(&self, from: DeviceID, to: DeviceID, data: Data) -> Result<()> {
        let Data { mut data } = data;

        // extract data kind
        if data.remaining() < 1 {
            return Err(Error::InvalidData);
        }

        let kind = data.get_u8();
        let kind = DataKind::try_from(kind).map_err(|_| Error::InvalidData)?;

        match kind {
            DataKind::Network => {
                if data.remaining() < size_of::<NetId>() {
                    return Err(Error::InvalidData);
                }

                let mut net_id = NetId::default();
                data.copy_to_slice(&mut net_id);

                let networks = self.networks.pin_owned();
                match networks.get(&net_id) {
                    Some(network) => {
                        network.process_data(from, to, data).await?;
                    }
                    None => {
                        trace!("received data packet for unknown network {}", net_id);
                    }
                }
            }
        }

        Ok(())
    }

    /// Process p2p message
    async fn process_p2p(&self, from: SocketAddr, binding: Binding) -> Result<()> {
        self.topology.process_p2p_message(from, binding).await?;
        Ok(())
    }

    /// Process remote packet from udp socket
    async fn process_remote_packet(&self, from: SocketAddr, data: Bytes) -> Result<()> {
        let Packet { header, body } = Packet::decode(data)?;

        match body {
            PacketBody::Data(data) => {
                self.process_data(header.from, header.to, data).await?;
            }
            PacketBody::P2P(binding) => {
                self.process_p2p(from, binding).await?;
            }
            PacketBody::KeyExchange(kex) => {
                self.topology.process_kex(header.from, kex).await?;
            }
            _ => {}
        }

        Ok(())
    }

    /// Run socket loop
    pub(crate) async fn run(&self) {
        loop {
            let mut buf = BytesMut::with_capacity(4096);
            match self.transport.recv_buf(&mut buf).await {
                Ok((_, from)) => {
                    let r = self.process_remote_packet(from, buf.freeze()).await;
                    if let Err(e) = r {
                        match e {
                            Error::NoSuchNetwork(_) | Error::PeerNotFound => {}
                            _ => error!(error=?e, "can't process remote packet"),
                        }
                    }
                }
                Err(e) if e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::WouldBlock => {
                    // todo: check stop
                }
                Err(e) if e.kind() == ErrorKind::ConnectionReset => {}
                Err(e) => {
                    if let Some(raw_error) = e.raw_os_error() {
                        if raw_error == 10052 {
                            // udp socket ttl expired, no need to log
                            continue;
                        }
                    }

                    error!("receive packet error: {}, kind: {}", e, e.kind());
                }
            }
        }
    }
}
