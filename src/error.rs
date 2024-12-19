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

use ringlink_identity::DeviceID;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("openssl: {0}")]
    Openssl(#[from] openssl::error::ErrorStack),

    #[error("io: {0}")]
    IOError(#[from] std::io::Error),

    #[error("peer exist")]
    PeerExists,

    #[error("peer conflict")]
    PeerConflict,

    #[error("peer not found")]
    PeerNotFound,

    #[error("no such network {0}")]
    NoSuchNetwork(ringlink_protocol::NetId),

    #[error("protocol: {0}")]
    Protocol(#[from] ringlink_protocol::Error),

    #[error("{0}")]
    Identity(#[from] ringlink_identity::Error),

    #[error("p2p {0}")]
    P2P(#[from] ringlink_p2p::Error),

    #[error("peer {0} unreachable")]
    PeerUnreachable(DeviceID),

    #[error("invalid data")]
    InvalidData,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
