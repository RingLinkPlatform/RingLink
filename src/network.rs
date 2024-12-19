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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::sync::broadcast::error::RecvError;
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};

use crate::codec::DataKind;
use crate::crypto::IV_LEN;
use crate::error::{Error, Result};
use crate::path::{Path, PathMeta};
use crate::peer::Peer;
use crate::topology::Topology;
use ringlink_identity::{DeviceID, Identity};
use ringlink_p2p::AgentEvent;
use ringlink_protocol::body::Data;
use ringlink_protocol::{NetId, Packet, PacketBody};
use ringlink_transport::Transport;

/// Implement this trait to receive data events
#[async_trait::async_trait]
pub trait DataListener {
    /// This method is called when a [PacketBody::Data] packet is received
    async fn on_data(&self, device: DeviceID, data: Bytes);
}

/// [DefaultListener] do nothing
struct DefaultListener;

#[async_trait::async_trait]
impl DataListener for DefaultListener {
    async fn on_data(&self, _device: DeviceID, _data: Bytes) {}
}

struct Inner<Trans> {
    /// network id
    id: NetId,
    /// self identity
    identity: Identity,
    /// network members
    members: ArcSwap<HashMap<DeviceID, Arc<Peer<Trans>>>>,
    /// paths to peers
    paths: ArcSwap<HashMap<DeviceID, Path>>,
    /// topology
    topology: Topology<Trans>,

    /// data subscriber
    subscriber: ArcSwap<Box<dyn DataListener + Send + Sync + 'static>>,

    stopped: AtomicBool,
}

pub struct Network<Trans> {
    inner: Arc<Inner<Trans>>,
    /// network task join handles
    tasks: Arc<Vec<JoinHandle<()>>>,
}

impl<Trans> Network<Trans>
where
    Trans: Transport + 'static,
{
    pub(crate) fn connect(
        id: NetId,
        identity: Identity,
        topology: Topology<Trans>,
    ) -> Result<Self> {
        let inner = Arc::new(Inner {
            id,
            identity,
            members: Default::default(),
            paths: Default::default(),
            topology,
            subscriber: ArcSwap::from_pointee(Box::new(DefaultListener)),
            stopped: AtomicBool::new(false),
        });

        let mut tasks = vec![];
        {
            let inner = inner.clone();
            let handle = tokio::spawn(async move {
                inner.watch_state().await;
            });
            tasks.push(handle);
        }

        Ok(Network {
            inner,
            tasks: Arc::new(tasks),
        })
    }

    /// Get network id
    pub fn id(&self) -> NetId {
        self.inner.id
    }

    /// Get network specific path
    pub fn paths(&self) -> HashMap<DeviceID, Path> {
        let paths = self.inner.paths.load();

        HashMap::clone(&paths)
    }

    /// Set network paths
    pub fn set_paths(&self, paths: HashMap<DeviceID, Path>) {
        self.inner.set_paths(paths)
    }

    /// Add a member to this network
    ///
    /// Member must be in the topology, otherwise this method will return an error
    pub fn add_member(&self, id: DeviceID) -> Result<()> {
        let peer = self
            .inner
            .topology
            .get_peer(id)
            .ok_or(Error::PeerNotFound)?;
        self.inner.members.rcu(|old| {
            let mut new = HashMap::clone(&old);
            new.insert(id, peer.clone());
            new
        });

        Ok(())
    }

    /// Remove a member from this network
    pub fn remove_member(&self, id: DeviceID) {
        self.inner.members.rcu(|old| {
            let mut new = HashMap::clone(&old);
            new.remove(&id);
            new
        });
    }

    /// Get all members in this network
    pub fn members(&self) -> Vec<DeviceID> {
        let members = self.inner.members.load();
        members.keys().copied().collect()
    }

    /// Stop this network
    ///
    /// Must be called before disconnect
    pub fn stop(&self) {
        self.unsubscribe();
        for task in &*self.tasks {
            task.abort();
        }

        self.inner.stopped.store(true, Ordering::Relaxed);
    }

    /// Check if this network is stopped
    pub fn stopped(&self) -> bool {
        self.inner.stopped.load(Ordering::Relaxed)
    }

    /// Lookup a path method for a peer
    fn lookup_method(&self, target: DeviceID) -> Option<Path> {
        let guard = self.inner.paths.load();
        guard.get(&target).copied()
    }

    /// Execute a closure with a peer in this network
    ///
    /// # Returns
    /// None if peer is not in this network
    fn execute_peer<F, R>(&self, id: DeviceID, f: F) -> Option<R>
    where
        F: FnOnce(&Peer<Trans>) -> R,
    {
        let guard = self.inner.members.load();
        guard.get(&id).map(|it| f(&it))
    }

    /// Subscribe to data events
    ///
    /// The listener will be called when a [PacketBody::Data] packet is received
    pub fn subscribe<Listener>(&self, listener: Listener)
    where
        Listener: DataListener + Send + Sync + 'static,
    {
        let listener = Box::new(listener);

        self.inner.subscriber.store(Arc::new(listener))
    }

    /// Unsubscribe release previous subscribed listener if exists
    ///
    /// This method has no effect if no listener is subscribed
    pub fn unsubscribe(&self) {
        self.inner
            .subscriber
            .store(Arc::new(Box::new(DefaultListener)));
    }

    /// Send data packet to a peer in this network
    ///
    /// # Arguments
    /// * `target` - target device id
    /// * `data` - data to send
    pub async fn send_data(&self, target: DeviceID, data: &[u8]) -> Result<()> {
        let method = self
            .lookup_method(target)
            .ok_or_else(|| Error::PeerUnreachable(target))?;

        let (data, iv) = self
            .execute_peer(target, |p| p.encrypt(data))
            .ok_or(Error::PeerNotFound)??;

        let mut buff = BytesMut::with_capacity(data.len() + 16);
        buff.put_u8(DataKind::Network as u8);
        buff.put_slice(&self.inner.id);
        buff.put_slice(&iv);
        buff.put(data);

        let data = Data {
            data: buff.freeze(),
        };
        let packet = Packet::new(self.inner.identity.id(), target, PacketBody::Data(data));
        let buff = packet.encode_into_bytes();

        self.inner.topology.send_via(method, &buff).await
    }

    /// Broadcast data packet to all peers in this network
    ///
    /// # Arguments
    /// * `data` - data to send
    pub async fn broadcast(&self, data: &[u8]) -> Result<()> {
        let members = self.inner.members.load();
        for id in members.keys() {
            if *id == self.inner.identity.id() {
                continue;
            }

            let _ = self.send_data(*id, data).await;
        }

        Ok(())
    }

    /// Process [PacketBody::Data] packet
    pub(crate) async fn process_data(
        &self,
        from: DeviceID,
        to: DeviceID,
        mut data: Bytes,
    ) -> Result<()> {
        if to != self.inner.identity.id() {
            warn!(
                "target device id[{}] not match self id[{}], ignore",
                to,
                self.inner.identity.id()
            );
        } else {
            // extract crypto IV
            if data.remaining() < IV_LEN {
                return Err(Error::Protocol(ringlink_protocol::Error::InsufficientData));
            }

            let iv = data.copy_to_bytes(IV_LEN);
            let r = self.execute_peer(from, |p| p.decrypt(&data, &iv));
            let data = match r {
                Some(Ok(data)) => data,
                Some(Err(e)) => {
                    debug!("decrypt packet failed: {}", e);
                    return Ok(());
                }
                None => {
                    trace!("received unknown peer[{}] packet", from);
                    return Ok(());
                }
            };

            let subscriber = self.inner.subscriber.load();
            subscriber.on_data(from, Bytes::from(data)).await;
        }
        Ok(())
    }
}

impl<Trans> Inner<Trans> {
    /// Set network paths, this method will merge new paths with current paths as well as override paths
    fn set_paths(&self, paths: HashMap<DeviceID, Path>) {
        self.paths.rcu(|current| {
            let mut new_paths = HashMap::clone(&current);

            // merge new paths with current paths
            for p in &paths {
                new_paths.insert(*p.0, *p.1);
            }

            new_paths
        });
    }

    /// Refresh paths for given targets
    fn refresh_paths_for(&self, targets: &[DeviceID])
    where
        Trans: Transport + 'static,
    {
        self.paths.rcu(|current| {
            let mut new_paths = HashMap::clone(&current);
            for target in targets {
                let address = self
                    .topology
                    .get_peer(*target)
                    .and_then(|p| p.agent().address());
                match address {
                    Some(address) => {
                        let path = Path::new(*target, PathMeta::Direct, address);
                        new_paths.insert(*target, path);
                    }
                    None => {}
                }
            }
            new_paths
        });
    }
}

impl<Trans> Inner<Trans>
where
    Trans: Transport + 'static,
{
    /// Called when a peer p2p state changed
    fn on_peer_state_changed(&self, id: DeviceID, _: AgentEvent) {
        self.refresh_paths_for(&[id]);
    }

    pub(super) async fn watch_state(&self) {
        let mut receiver = self.topology.subscribe_p2p();

        loop {
            match receiver.recv().await {
                Ok((id, state)) => {
                    let members = self.members.load();
                    if members.contains_key(&id) {
                        self.on_peer_state_changed(id, state);
                    }
                }
                Err(RecvError::Closed) => {
                    break;
                }
                Err(RecvError::Lagged(_)) => {
                    continue;
                }
            }
        }
    }
}

impl<Trans> Clone for Network<Trans> {
    fn clone(&self) -> Self {
        Network {
            inner: self.inner.clone(),
            tasks: self.tasks.clone(),
        }
    }
}

/// Returns a new [`ListenerFn`]  with the given closure
///
/// This lets you build a [`DataListener`] from a closure.
pub fn listener_fn<F>(f: F) -> ListenerFn<F> {
    ListenerFn { f }
}

/// A [`DataListener`] implemented by a closure
pub struct ListenerFn<F> {
    f: F,
}

#[async_trait]
impl<F> DataListener for ListenerFn<F>
where
    F: Fn(DeviceID, Bytes) + Send + Sync + 'static,
{
    async fn on_data(&self, device: DeviceID, data: Bytes) {
        (self.f)(device, data)
    }
}
