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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::sync::broadcast::Receiver;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{StreamExt, StreamMap};
use tracing::warn;

use crate::error::Error;
use crate::path::Path;
use crate::peer::Peer;
use ringlink_identity::{DeviceID, Identity, PublicIdentity};
use ringlink_p2p::{AgentEvent, Candidate, P2PManager};
use ringlink_protocol::body::{Binding, KeyExchange};
use ringlink_transport::Transport;

pub struct Inner<T> {
    identity: Identity,
    peers: ArcSwap<HashMap<DeviceID, Arc<Peer<T>>>>,

    p2p: Arc<P2PManager<T>>,
    p2p_watch_tx: mpsc::Sender<DeviceID>,
    p2p_state_change: broadcast::Sender<(DeviceID, AgentEvent)>,
    transport: T,
}

/// Topology manages peers communication across RingLink
pub struct Topology<T> {
    inner: Arc<Inner<T>>,
    tasks: Arc<Vec<JoinHandle<()>>>,
}

impl<T> Topology<T>
where
    T: Transport + 'static,
{
    /// Create a new topology
    pub fn new(
        transport: T,
        identity: Identity,
        p2p: Arc<P2PManager<T>>,
    ) -> Result<Topology<T>, Error> {
        let (p2p_watch_tx, p2p_watch_rx) = mpsc::channel(32);

        let inner = Arc::new(Inner {
            identity,
            peers: Default::default(),
            p2p,
            p2p_watch_tx,
            p2p_state_change: broadcast::channel(128).0,
            transport,
        });

        let mut tasks = Vec::new();
        {
            let inner = inner.clone();
            tasks.push(tokio::spawn(async move {
                inner.watch_p2p(p2p_watch_rx).await;
            }));
        }

        Ok(Topology {
            inner,
            tasks: Arc::new(tasks),
        })
    }

    /// Get a peer by id
    pub fn get_peer(&self, id: DeviceID) -> Option<Arc<Peer<T>>> {
        let guard = self.inner.peers.load();
        guard.get(&id).cloned()
    }

    /// Add a peer to topology, return peer if success
    pub async fn add_peer(&self, identity: PublicIdentity) -> Result<Arc<Peer<T>>, Error> {
        if identity.id() == self.inner.identity.id() {
            return Err(Error::PeerExists);
        }

        let peers = self.inner.peers.load();
        match peers.get(&identity.id()) {
            Some(current) => {
                // check peer id conflict
                if is_conflict(&current.identity(), &identity) {
                    warn!(
                        "peer conflict detected, identity {:?} and {:?} has same id {}",
                        identity,
                        current.identity(),
                        identity.id()
                    );
                    return Err(Error::PeerConflict);
                }

                Ok(current.clone())
            }
            None => {
                let peer =
                    Peer::new(&self.inner.identity, identity.clone(), &self.inner.p2p).await?;
                let peer = Arc::new(peer);
                drop(peers);

                self.inner.peers.rcu(|old| {
                    let mut peers = HashMap::clone(&old);
                    peers.insert(peer.id(), peer.clone());
                    peers
                });
                _ = self.inner.p2p_watch_tx.send(peer.id()).await;

                Ok(peer)
            }
        }
    }

    /// Remove a peer from topology
    pub fn remove_peer(&self, id: DeviceID) {
        self.inner.peers.rcu(|old| {
            let mut peers = HashMap::clone(&old);
            peers.remove(&id);
            peers
        });
    }

    /// Send data to a peer
    pub(crate) async fn send_via(&self, path: Path, data: &[u8]) -> Result<(), Error> {
        if let Some(endpoint) = path.endpoint {
            self.inner.transport.send(data, endpoint).await?;
            Ok(())
        } else {
            Err(Error::PeerUnreachable(path.target))
        }
    }

    pub(crate) async fn process_p2p_message(
        &self,
        from: SocketAddr,
        binding: Binding,
    ) -> Result<(), Error> {
        self.inner.p2p.handle_input(binding, from).await?;

        Ok(())
    }

    pub(crate) async fn process_kex(&self, from: DeviceID, kex: KeyExchange) -> Result<(), Error> {
        if let Some(peer) = self.get_peer(from) {
            peer.process_kex(kex).await?;
        }

        Ok(())
    }

    /// Set remote peer candidates
    ///
    /// Candidates are used to establish p2p connection.
    ///
    /// Calling this method will replace the current candidates with the new ones.
    pub async fn set_remote_candidates<I>(&self, id: DeviceID, candidates: I)
    where
        I: IntoIterator<Item = Candidate>,
    {
        self.inner
            .p2p
            .set_remote_candidates(
                id,
                candidates
                    .into_iter()
                    .filter_map(|it| it.try_into().ok())
                    .collect(),
            )
            .await;
    }

    /// Stop topology
    ///
    /// This method will stop all tasks in topology
    pub fn stop(&self) {
        self.inner.p2p.stop();

        for task in &*self.tasks {
            task.abort();
        }
    }

    pub(crate) fn subscribe_p2p(&self) -> Receiver<(DeviceID, AgentEvent)> {
        self.inner.p2p_state_change.subscribe()
    }
}

impl<T> Clone for Topology<T> {
    fn clone(&self) -> Self {
        Topology {
            inner: self.inner.clone(),
            tasks: self.tasks.clone(),
        }
    }
}

impl<T> Inner<T> {
    /// Watch peers p2p state
    ///
    /// # Arguments
    /// * `rx` - send device id to add to watch list
    async fn watch_p2p(&self, mut rx: mpsc::Receiver<DeviceID>) {
        let mut map = StreamMap::<DeviceID, BroadcastStream<AgentEvent>>::new();

        loop {
            tokio::select! {
                Some((id, state)) = map.next() => {
                    if let Ok(state) = state {
                        // notify state change
                        _ = self.p2p_state_change.send((id, state));
                    } else {
                        // peer is removed
                        map.remove(&id);
                    }
                },
                Some(id) = rx.recv() => {
                    let peers = self.peers.load();
                    if let Some(peer) = peers.get(&id) {
                        let rx = peer.agent().subscribe_state();
                          map.insert(id, BroadcastStream::new(rx));
                    }
                }
            }
        }
    }
}

fn is_conflict(old: &PublicIdentity, new: &PublicIdentity) -> bool {
    old.id() == new.id() && old.public_key() != new.public_key()
}
