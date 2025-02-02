// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

#[macro_use]
extern crate lazy_static;

use anyhow::*;
use attestation_agent::AttestationAgent;
use clap::{App, Arg};
use log::*;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

mod grpc;

const DEFAULT_KEYPROVIDER_ADDR: &str = "127.0.0.1:50000";
const DEFAULT_GETRESOURCE_ADDR: &str = "127.0.0.1:50001";
const DEFAULT_GETEVIDENCE_ADDR: &str = "127.0.0.1:50002";
const DEFAULT_AGENT_ADDR: &str = "";

lazy_static! {
    pub static ref ATTESTATION_AGENT: Arc<Mutex<AttestationAgent>> =
        Arc::new(Mutex::new(AttestationAgent::new()));
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let app_matches = App::new(grpc::AGENT_NAME)
        .version(env!("CARGO_PKG_VERSION"))
        .arg(
            Arg::with_name("KeyProvider gRPC socket addr")
                .long("keyprovider_sock")
                .takes_value(true)
                .help("This socket address which the KeyProvider gRPC service will listen to, for example: --keyprovider_sock 127.0.0.1:11223",
                ),
        )
        .arg(
            Arg::with_name("GetResource gRPC socket addr")
                .long("getresource_sock")
                .takes_value(true)
                .help("This socket address which the GetResource gRPC service will listen to, for example: --getresource_sock 127.0.0.1:11223",
                ),
        )
        .arg(
            Arg::with_name("GetEvidence gRPC socket addr")
                .long("getevidence_sock")
                .takes_value(true)
                .help("This socket address which the GetEvidence gRPC service will listen to, for example: --getevidence_sock 127.0.0.1:11223"
                )
        ).arg(
            Arg::with_name("Agent ttRPC addr")
                .long("agent_address")
                .takes_value(true)
                .help("This socket address which the Agent ttRPC service binded to, for example: --agent_address 127.0.0.1:11223"
                )
        )
        .get_matches();

    let keyprovider_socket = app_matches
        .value_of("KeyProvider gRPC socket addr")
        .unwrap_or(DEFAULT_KEYPROVIDER_ADDR)
        .parse::<SocketAddr>()?;

    let getresource_socket = app_matches
        .value_of("GetResource gRPC socket addr")
        .unwrap_or(DEFAULT_GETRESOURCE_ADDR)
        .parse::<SocketAddr>()?;

    let getevidence_socket = app_matches
        .value_of("GetEvidence gRPC socket addr")
        .unwrap_or(DEFAULT_GETEVIDENCE_ADDR)
        .parse::<SocketAddr>()?;

    let agent_addr = app_matches
        .value_of("Agent ttRPC addr")
        .unwrap_or(DEFAULT_AGENT_ADDR);

    debug!(
        "KeyProvider gRPC service listening on: {:?}",
        keyprovider_socket
    );
    debug!(
        "GetResource gRPC service listening on: {:?}",
        getresource_socket
    );
    debug!(
        "GetEvidence gRPC service listening on: {:?}",
        getevidence_socket
    );

    debug!("Agent service listening on: {:?}", agent_addr);

    let keyprovider_server = grpc::keyprovider::start_service(keyprovider_socket);
    let getresource_server = grpc::getresource::start_service(getresource_socket);
    if agent_addr.len() < 1 {
        tokio::join!(keyprovider_server, getresource_server).0
    } else {
        let getevidence_server = grpc::getevidence::start_service(getevidence_socket, agent_addr);
        tokio::join!(keyprovider_server, getresource_server, getevidence_server).0
    }
}
