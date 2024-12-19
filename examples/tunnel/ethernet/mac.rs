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

use std::fmt::{Display, Formatter};

use anyhow::Result;
use openssl::hash::{Hasher, MessageDigest};

use ringlink_identity::Identity;
use ringlink_protocol::NetId;

/// Ethernet MAC
#[derive(Copy, Clone, Default, Hash, Eq, PartialEq)]
pub struct MAC(pub [u8; 6]);

impl AsRef<[u8]> for MAC {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for MAC {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Display for MAC {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s = self
            .0
            .iter()
            .map(|it| format!("{:02x}", it))
            .collect::<Vec<_>>()
            .join(":");

        write!(f, "{}", s)
    }
}

impl MAC {
    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xff; 6]
    }

    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 == 0x01
    }

    /// compute MAC address from identity and network id
    pub fn derive(identity: &Identity, network: NetId) -> Result<MAC> {
        let mut hasher = Hasher::new(MessageDigest::sha512())?;

        let sk = identity.private_key();
        for _ in 0..15 {
            hasher.update(&sk)?;
            hasher.update(&network)?;
        }

        let digest = hasher.finish()?;
        let mut mac = [0u8; 6];
        mac[0] = (network[0] & 0xfe) | 0b10; // first byte of network, locally administered addresses, unicast

        mac[1..].copy_from_slice(&digest[0..5]);

        Ok(MAC(mac))
    }
}
