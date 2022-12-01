// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use attestation_agent::AttestationAPIs;
use log::*;
use std::net::SocketAddr;
use std::sync::Arc;
use tonic::{transport::Server, Request, Response, Status};

use crate::grpc::AGENT_NAME;
use crate::ATTESTATION_AGENT;

use get_evidence::get_evidence_service_server::{GetEvidenceService, GetEvidenceServiceServer};

use self::get_evidence::{GetEvidenceRequest, GetEvidenceResponse};

pub mod get_evidence {
    tonic::include_proto!("getevidence");
}

#[derive(Debug, Default)]
pub struct GetEvidence{}

#[tonic::async_trait]
impl GetEvidenceService for GetEvidence{
    async fn get_evidence(&self,request:Request<GetEvidenceRequest>,)
    -> Result<Response<GetEvidenceResponse>,Status> {
        let request = request.into_inner();

        let attestation_agent_mutex_clone = Arc::clone(&ATTESTATION_AGENT);
        let mut attestation_agent = attestation_agent_mutex_clone.lock().await;

        debug!("Generate evidence");

        let target_evidence = attestation_agent.get_container_evidence(request.container_id, request.nonce).await.map_err(|e| {
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

pub async fn start_service(socket: SocketAddr) -> Result<()> {
    let service = GetEvidence::default();
    let _server = Server::builder()
        .add_service(GetEvidenceServiceServer::new(service))
        .serve(socket)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests{
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_get_evicence(){
        let nonce = "12345678".as_bytes();
        let request_body = GetEvidenceRequest{
            container_id: "0".to_string(),
            nonce:nonce.to_vec()
        };
        let req = Request::new(request_body);
        let service = GetEvidence::default();
        let res = service.get_evidence(req).await;
        assert!(res.is_ok() && !res.is_err());
        let evidence = res.unwrap().into_inner().evidence;
        print!("evidence is {:?}",evidence);
    }
}