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
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use base64::engine::general_purpose::STANDARD;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use bytes::BytesMut;
use clap::{Parser, Subcommand};
use openssl::rand::rand_bytes;
use serde::{Deserialize, Serialize};

use crate::ethernet::{EthernetLayer, MAC};
use crate::tap::{TapControl, IO};
use ringlink_core::{RingLink, Topology};
use ringlink_identity::{hex, Identity, PublicIdentity};
use ringlink_p2p::{Candidate, CandidateType, P2PManager};
use ringlink_protocol::NetId;
use ringlink_transport::{Transport, UdpTransport};
use tokio::runtime::Handle;

mod ethernet;
mod tap;

#[derive(Serialize, Deserialize)]
pub struct PeerConfig {
    pub public_key: String,
    pub endpoint: Option<SocketAddr>,
}

#[derive(Serialize, Deserialize)]
pub struct NetworkConfig {
    pub id: NetId,
    pub ip: String,
    pub mtu: Option<u16>,
    pub if_name: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub listen: SocketAddr,
    pub identity_file: String,
    pub peers: Vec<PeerConfig>,
    pub network: NetworkConfig,
}

#[derive(Parser)]
struct Args {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[clap(subcommand)]
    Identity(IdentityCommand),
    #[clap(subcommand)]
    Network(NetworkCommand),
    Run(RunCommand),
}

#[derive(Subcommand)]
#[clap(about = "manage RingLink identity")]
enum IdentityCommand {
    #[clap(about = "generate RingLink identity", visible_aliases = ["gen", "g"])]
    Generate {
        #[clap(
            short,
            long,
            help = "output identity file",
            default_value = "identity.secret"
        )]
        output: PathBuf,
        #[clap(short, long, help = "force override exist identity file")]
        force: bool,
    },
    #[clap(about = "print a exist identity")]
    Print {
        #[clap(
            short,
            long,
            help = "input identity file",
            default_value = "identity.secret"
        )]
        input: PathBuf,
    },
}

#[derive(Subcommand)]
#[clap(about = "RingLink network utils")]
enum NetworkCommand {
    #[clap(about = "generate a random network id")]
    GenerateID,
}

#[derive(Parser)]
#[clap(about = "run RingLink")]
struct RunCommand {
    #[clap(long, short, help = "config file path", default_value = "config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Identity(cmd) => {
            run_identity_command(cmd)?;
        }
        Command::Network(cmd) => {
            run_network_command(cmd)?;
        }
        Command::Run(cmd) => {
            tracing_subscriber::fmt::init();

            let content = std::fs::read_to_string(cmd.config)?;
            let config: Config = toml::from_str(&content)?;
            run_ringlink(config).await?;
        }
    }

    Ok(())
}

fn run_identity_command(cmd: IdentityCommand) -> anyhow::Result<()> {
    match cmd {
        IdentityCommand::Generate { output, force } => {
            if output.exists() && !force {
                println!(
                    "a identity already exist on {}",
                    output.canonicalize()?.display()
                );
                return Ok(());
            }

            println!("generating a new identity");
            let identity = Identity::generate()?;
            println!("identity generated!");

            print_identity(&identity);

            if output.exists() {
                println!("overriding identity on {}", output.display());
            } else {
                println!("saving identity to {}", output.display());
            }

            std::fs::write(output, serde_json::to_string(&identity)?)?;
        }
        IdentityCommand::Print { input } => {
            let content = std::fs::read_to_string(input)?;
            let identity: Identity = serde_json::from_str(&content)?;
            print_identity(&identity);
        }
    }

    Ok(())
}

/// Print identity public keys to stdout
fn print_identity(identity: &Identity) {
    let public_identity = identity.public_identity().unwrap();

    println!("client id: {}", identity.id());
    println!(
        "client public key: {}",
        STANDARD.encode(public_identity.public_key())
    );
}

fn run_network_command(cmd: NetworkCommand) -> anyhow::Result<()> {
    match cmd {
        NetworkCommand::GenerateID => {
            let mut out = [0u8; 4];
            rand_bytes(&mut out)?;

            let id = hex::encode(&out);

            println!("{}", id);
        }
    }

    Ok(())
}

async fn run_ringlink(config: Config) -> anyhow::Result<()> {
    // first, initialize the udp socket, bind to the listen address
    let transport = UdpTransport::new(config.listen).await?;

    // load the identity from the file
    let identity = load_identity(&config)?;

    // create a p2p service
    let p2p = P2PManager::new(identity.clone(), transport.clone()?)?;
    // initialize the topology
    let topology = Topology::new(transport.clone()?, identity.clone(), Arc::new(p2p))?;

    // add peers to the topology
    let mut members = HashSet::new();
    for peer in &config.peers {
        let public_key = BASE64_STANDARD.decode(&peer.public_key)?;
        let public_identity = PublicIdentity::new(public_key)?;
        // collect peers id for later set network members
        members.insert(public_identity.id());

        let p = topology.add_peer(public_identity).await?;

        if let Some(endpoint) = peer.endpoint {
            // prepare the candidate for p2p service
            let mut candidates = HashSet::new();
            candidates.insert(Candidate {
                id: 0,
                typ: CandidateType::Host,
                priority: 0,
                address: endpoint,
            });
            p.set_candidates(candidates).await;
        }
    }

    // initialize the ringlink service
    let ringlink = RingLink::new(identity.clone(), transport.clone()?, topology);
    // then, connect to the network and set the members
    let network = ringlink.connect(config.network.id)?;
    for member in members {
        _ = network.add_member(member);
    }

    // attach the ethernet layer to this ringlink network
    let (rx, layer) = EthernetLayer::new(network);
    let mac = MAC::derive(&identity, config.network.id)?;

    // create a tap device for IO
    let io = create_tap(&config, mac)?;

    {
        // spawn a new thread for blocking tap device read
        let rt = Handle::current();
        let io = io.clone();
        std::thread::spawn(move || loop {
            let mut buff = BytesMut::zeroed(4096);
            match io.read(&mut buff) {
                Ok(n) => {
                    unsafe {
                        buff.set_len(n);
                    }

                    // send the frame to the ethernet layer for processing
                    _ = rt.block_on(layer.process_local_frame_buff(buff.freeze()));
                }
                Err(_) => {}
            }
        });
    }

    // spawn a new thread for blocking tap device write
    tokio::task::spawn_blocking(move || loop {
        // read from the ethernet layer and write to the tap device
        match rx.recv() {
            Ok((_, buff)) => {
                _ = io.write(&buff);
            }
            Err(_) => {}
        }
    })
    .await?;

    Ok(())
}

/// Load the identity from the file
///
/// # Errors
/// Error if the identity file is not found or invalid
fn load_identity(config: &Config) -> anyhow::Result<Identity> {
    let content = std::fs::read_to_string(&config.identity_file)?;

    let identity = serde_json::from_str(&content)?;
    Ok(identity)
}

/// Create a tap device with the given configuration
///
/// # Arguments
/// * `mac` - The MAC address for the tap device, can be derived from the identity and network id
fn create_tap(config: &Config, mac: MAC) -> anyhow::Result<Arc<IO>> {
    let name = if let Some(ref name) = config.network.if_name {
        name.clone()
    } else {
        format!("{}", config.network.id)
    };

    // create a tap device with the given name and bring it up
    let mut control = TapControl::new(&name)?;
    let io = control.open()?;
    control.set_mac(mac.0)?;
    control.up()?;

    // set the ip address and mtu for the tap device
    // must be done after the device is up
    let (ip, prefix) = parse_cidr(&config.network.ip)?;
    match ip {
        IpAddr::V4(v4) => {
            control.add_ipv4(v4, prefix)?;
        }
        IpAddr::V6(v6) => {
            control.add_ipv6(v6, prefix)?;
        }
    }

    if let Some(mtu) = config.network.mtu {
        control.set_mtu(mtu)?;
    }

    let io = Arc::new(io);

    Ok(io)
}

/// Parse the ip address and prefix from the given string
///
/// If the prefix is not provided, default to 32
///
/// # Example
/// ```rust
/// fn main() {
///     let cidr = "192.168.0.1/24";
///     let (ip, prefix) = parse_cidr(cidr).unwrap();
/// }
/// ```
fn parse_cidr(s: &str) -> anyhow::Result<(IpAddr, u8)> {
    let mut parts = s.split('/');
    let ip = parts.next().context("missing ip address")?;
    let ip = ip.parse::<IpAddr>().context("invalid ip address")?;

    let prefix = parts
        .next()
        .and_then(|it| it.parse::<u8>().ok())
        .unwrap_or(32);

    Ok((ip, prefix))
}
