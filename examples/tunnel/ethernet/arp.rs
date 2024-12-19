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

use papaya::HashMap;

use ringlink_identity::DeviceID;

use crate::ethernet::mac::MAC;

pub struct ArpTable {
    entries: HashMap<MAC, DeviceID>,
}

impl ArpTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::with_capacity(128),
        }
    }

    /// lookup a device id by MAC address
    pub fn lookup(&self, mac: MAC) -> Option<DeviceID> {
        let entries = self.entries.pin();
        entries.get(&mac).copied()
    }

    /// insert a new entry into the ARP table
    pub fn insert(&self, mac: MAC, device: DeviceID) {
        let entries = self.entries.pin();
        if !entries.contains_key(&mac) {
            entries.insert(mac, device);
        }
    }

    /// remove an entry from the ARP table
    #[allow(dead_code)]
    pub fn remove(&self, mac: MAC) {
        let entries = self.entries.pin();
        entries.remove(&mac);
    }
}
