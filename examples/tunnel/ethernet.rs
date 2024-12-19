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

use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use anyhow::{bail, Result};
use bytes::Bytes;
use flume::Receiver;
use ringlink_core::{DataListener, Network};
use ringlink_identity::DeviceID;
use ringlink_transport::{async_trait, UdpTransport};

use crate::ethernet::arp::ArpTable;
pub use crate::ethernet::mac::MAC;

mod arp;
mod mac;

pub struct EthernetHeader {
    /// destination MAC
    pub dst: MAC,
    /// source MAC
    pub src: MAC,
    /// optional vlan tag
    #[allow(unused)]
    pub tag: Option<[u8; 4]>,
}

impl Debug for EthernetHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let src = self
            .src
            .0
            .iter()
            .map(|it| format!("{:02x}", it))
            .collect::<Vec<_>>()
            .join(":");
        let dst = self
            .dst
            .0
            .iter()
            .map(|it| format!("{:02x}", it))
            .collect::<Vec<_>>()
            .join(":");

        write!(f, "{} -> {}", src, dst)
    }
}

impl EthernetHeader {
    pub fn parse(frame: &[u8]) -> Result<Self> {
        if frame.len() < size_of::<MAC>() * 2 {
            bail!("invalid ethernet frame");
        }

        let dst = MAC(frame[0..6].try_into().expect("slice out of range"));
        let src = MAC(frame[6..12].try_into().expect("slice out of range"));

        // todo: parse vlan tag

        Ok(Self {
            dst,
            src,
            tag: None,
        })
    }
}

pub struct EthernetLayer {
    network: Network<UdpTransport>,
    arp_table: Arc<ArpTable>,
}

impl EthernetLayer {
    pub fn new(network: Network<UdpTransport>) -> (Receiver<(DeviceID, Bytes)>, EthernetLayer) {
        let arp_table = Arc::new(ArpTable::new());
        let (rx, listener) = Listener::new(arp_table.clone());
        network.subscribe(listener);

        (rx, EthernetLayer {
            network,
            arp_table,
        })
    }

    /// Process incoming ethernet frame
    pub async fn process_local_frame_buff(&self, frame: Bytes) -> Result<()> {

        let EthernetHeader { dst, .. } = EthernetHeader::parse(&frame)?;

        if dst.is_multicast() || dst.is_broadcast() {
            // broadcast frame
            self.network.broadcast(&frame).await?;
        } else {
            let id = self.arp_table.lookup(dst);
            match id {
                Some(id) => {
                    self.network.send_data(id, &frame).await?;
                }
                None => {
                    println!("unknown device id: {:?}", dst.0);
                }
            }
        }

        Ok(())
    }
}

struct Listener(flume::Sender<(DeviceID, Bytes)>, Arc<ArpTable>);

impl Listener {
    pub fn new(arp_table: Arc<ArpTable>) -> (Receiver<(DeviceID, Bytes)>, Listener) {
        let (tx, rx) = flume::bounded(40960);

        (rx, Listener(tx, arp_table))
    }
}

#[async_trait]
impl DataListener for Listener {
    async fn on_data(&self, device: DeviceID, data: Bytes) {
        if let Ok(ethernet) = EthernetHeader::parse(&data) {
            _ = self.1.insert(ethernet.src, device);
        }

        _ = self.0.try_send((device, data));
    }
}
