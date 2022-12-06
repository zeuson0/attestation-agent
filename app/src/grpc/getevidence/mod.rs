// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use attestation_agent::AttestationAPIs;
use futures::lock::Mutex;
use log::*;
use nix::libc;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::prelude::IntoRawFd;
use nix::sys::socket::{connect, socket, AddressFamily, SockAddr, SockFlag, SockType, UnixAddr};
use std::{net::SocketAddr};
use std::result::Result::Ok;
use std::sync::Arc;
use tonic::{transport::Server, Request, Response, Status};

use crate::grpc::AGENT_NAME;
use crate::ATTESTATION_AGENT;

use get_evidence::get_evidence_service_server::{GetEvidenceService, GetEvidenceServiceServer};

use self::get_evidence::{GetEvidenceRequest, GetEvidenceResponse};

use super::image::image::*;
use super::image::image_ttrpc::*;

pub mod get_evidence {
    tonic::include_proto!("getevidence");
}

#[derive(Debug)]
pub struct GetEvidence{
    client: Arc<Mutex<ImageClient>>
}


fn client_create_vsock_fd(cid: libc::c_uint, port: u32) -> Result<RawFd> {
    let fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .map_err(|e| anyhow!(e))?;

    let sock_addr = SockAddr::new_vsock(cid, port);

    connect(fd, &sock_addr).map_err(|e| anyhow!(e))?;

    Ok(fd)
}

fn create_ttrpc_client(
    server_address: String
) -> Result<ttrpc::Client> {
    if server_address.is_empty() {
        return Err(anyhow!("server address cannot be blank"));
    }

    let fields: Vec<&str> = server_address.split("://").collect();

    if fields.len() != 2 {
        return Err(anyhow!("invalid server address URI"));
    }

    let scheme = fields[0].to_lowercase();

    let fd: RawFd = match scheme.as_str() {
        // Formats:
        //
        // - "unix://absolute-path" (domain socket, or hybrid vsock!)
        //   (example: "unix:///tmp/domain.socket")
        //
        // - "unix://@absolute-path" (abstract socket)
        //   (example: "unix://@/tmp/abstract.socket")
        //
        "unix" => {
            let mut abstract_socket = false;

            let mut path = fields[1].to_string();

            if path.starts_with('@') {
                abstract_socket = true;

                // Remove the magic abstract-socket request character ('@').
                path = path[1..].to_string();
            }

            if abstract_socket {
                let socket_fd = match socket(
                    AddressFamily::Unix,
                    SockType::Stream,
                    SockFlag::empty(),
                    None,
                ) {
                    Ok(s) => s,
                    Err(e) => return Err(anyhow!(e).context("Failed to create Unix Domain socket")),
                };

                let unix_addr = match UnixAddr::new_abstract(path.as_bytes()) {
                    Ok(s) => s,
                    Err(e) => {
                        return Err(
                            anyhow!(e).context("Failed to create Unix Domain abstract socket")
                        )
                    }
                };

                let sock_addr = SockAddr::Unix(unix_addr);

                connect(socket_fd, &sock_addr).map_err(|e| {
                    anyhow!(e).context("Failed to connect to Unix Domain abstract socket")
                })?;

                socket_fd
            } else {
                let stream = match UnixStream::connect(path) {
                    Ok(s) => s,
                    Err(e) => {
                        return Err(
                            anyhow!(e).context("failed to create named UNIX Domain stream socket")
                        )
                    }
                };

                stream.into_raw_fd()
            }
        }
        // Format: "vsock://cid:port"
        "vsock" => {
            let addr: Vec<&str> = fields[1].split(':').collect();

            if addr.len() != 2 {
                return Err(anyhow!("invalid VSOCK server address URI"));
            }

            let cid: u32 = match addr[0] {
                "-1" | "" => libc::VMADDR_CID_ANY,
                _ => match addr[0].parse::<u32>() {
                    Ok(c) => c,
                    Err(e) => return Err(anyhow!(e).context("VSOCK CID is not numeric")),
                },
            };

            let port: u32 = match addr[1].parse::<u32>() {
                Ok(r) => r,
                Err(e) => return Err(anyhow!(e).context("VSOCK port is not numeric")),
            };

            client_create_vsock_fd(cid, port).map_err(|e| {
                anyhow!(e).context("failed to create VSOCK connection (check agent is running)")
            })?
        }
        _ => {
            return Err(anyhow!("invalid server address URI scheme: {:?}", scheme));
        }
    };

    Ok(ttrpc::Client::new(fd))
}

#[tonic::async_trait]
impl GetEvidenceService for GetEvidence{
    async fn get_evidence(&self,request:Request<GetEvidenceRequest>,)
    -> Result<Response<GetEvidenceResponse>,Status> {
        let request = request.into_inner();

        let attestation_agent_mutex_clone = Arc::clone(&ATTESTATION_AGENT);
        let mut attestation_agent = attestation_agent_mutex_clone.lock().await;

        debug!("Generate evidence");

        let client = self.client.lock().await;
        let ctx = ttrpc::context::with_timeout(2000);

        let req = MetaContainerRequest::default();
        req.set_container_id(request.container_id);

        let image_digest = client.meta_container(ctx, &req)?;

        let target_evidence = attestation_agent.get_container_evidence(image_digest.get_digest(), request.nonce).await.map_err(|e| {
            error!("Generate evidence failed: {}", e);
            Status::internal(format!(
                "[ERROR:{}] Generate evidence failed: {}",
                AGENT_NAME, e
            ))
        })?;

        debug!("Generate evidence successfully!");

        let reply = GetEvidenceResponse{
            evidence:target_evidence,
        };

        Result::Ok(Response::new(reply))
    }
}

pub async fn start_service(socket: SocketAddr, agent_addr: &str) -> Result<()> {

    let c = create_ttrpc_client(agent_addr.to_string())?;
    let i_c = ImageClient{
        client:c
    };

    let client = Arc::new(Mutex::new(i_c));
    let service = GetEvidence{
        client
    };

    let _server = Server::builder()
        .add_service(GetEvidenceServiceServer::new(service))
        .serve(socket)
        .await?;
    Ok(())
}

// #[cfg(test)]
// mod tests{
//     use super::*;

//     #[tokio::test(flavor = "multi_thread")]
//     async fn test_get_evicence(){
//         let nonce = "12345678".as_bytes();
//         let request_body = GetEvidenceRequest{
//             container_id: "0".to_string(),
//             nonce:nonce.to_vec()
//         };
//         let req = Request::new(request_body);
//         let service = GetEvidence::default();
//         let res = service.get_evidence(req).await;
//         assert!(res.is_ok() && !res.is_err());
//         let evidence = res.unwrap().into_inner().evidence;
//         print!("evidence is {:?}",evidence);
//     }
// }