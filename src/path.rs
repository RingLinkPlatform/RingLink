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

use std::net::SocketAddr;

use ringlink_identity::DeviceID;

#[derive(Clone, Copy, Hash, Eq, PartialEq, Debug)]
#[non_exhaustive]
pub enum PathMeta {
    /// p2p direct connect
    ///
    /// both client must be Direct
    Direct,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Path {
    pub target: DeviceID,
    pub meta: PathMeta,
    pub endpoint: Option<SocketAddr>,
}

impl Path {
    pub fn new(target: DeviceID, meta: PathMeta, endpoint: SocketAddr) -> Path {
        Path {
            target,
            meta,
            endpoint: Some(endpoint),
        }
    }

    pub fn empty(target: DeviceID, meta: PathMeta) -> Path {
        Path {
            target,
            meta,
            endpoint: None,
        }
    }
}
