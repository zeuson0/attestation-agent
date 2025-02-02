// This file is generated by ttrpc-compiler 0.4.2. Do not edit
// @generated

// https://github.com/Manishearth/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clipto_camel_casepy)]

#![cfg_attr(rustfmt, rustfmt_skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unsafe_code)]
#![allow(unused_imports)]
#![allow(unused_results)]
use protobuf::{CodedInputStream, CodedOutputStream, Message};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct ImageClient {
    client: ::ttrpc::Client,
}

impl ImageClient {
    pub fn new(client: ::ttrpc::Client) -> Self {
        ImageClient {
            client: client,
        }
    }

    pub fn pull_image(&self, ctx: ttrpc::context::Context, req: &super::image::PullImageRequest) -> ::ttrpc::Result<super::image::PullImageResponse> {
        let mut cres = super::image::PullImageResponse::new();
        ::ttrpc::client_request!(self, ctx, req, "grpc.Image", "PullImage", cres);
        Ok(cres)
    }

    pub fn meta_container(&self, ctx: ttrpc::context::Context, req: &super::image::MetaContainerRequest) -> ::ttrpc::Result<super::image::MetaContainerResponse> {
        let mut cres = super::image::MetaContainerResponse::new();
        ::ttrpc::client_request!(self, ctx, req, "grpc.Image", "MetaContainer", cres);
        Ok(cres)
    }
}

struct PullImageMethod {
    service: Arc<std::boxed::Box<dyn Image + Send + Sync>>,
}

impl ::ttrpc::MethodHandler for PullImageMethod {
    fn handler(&self, ctx: ::ttrpc::TtrpcContext, req: ::ttrpc::Request) -> ::ttrpc::Result<()> {
        ::ttrpc::request_handler!(self, ctx, req, image, PullImageRequest, pull_image);
        Ok(())
    }
}

struct MetaContainerMethod {
    service: Arc<std::boxed::Box<dyn Image + Send + Sync>>,
}

impl ::ttrpc::MethodHandler for MetaContainerMethod {
    fn handler(&self, ctx: ::ttrpc::TtrpcContext, req: ::ttrpc::Request) -> ::ttrpc::Result<()> {
        ::ttrpc::request_handler!(self, ctx, req, image, MetaContainerRequest, meta_container);
        Ok(())
    }
}

pub trait Image {
    fn pull_image(&self, _ctx: &::ttrpc::TtrpcContext, _req: super::image::PullImageRequest) -> ::ttrpc::Result<super::image::PullImageResponse> {
        Err(::ttrpc::Error::RpcStatus(::ttrpc::get_status(::ttrpc::Code::NOT_FOUND, "/grpc.Image/PullImage is not supported".to_string())))
    }
    fn meta_container(&self, _ctx: &::ttrpc::TtrpcContext, _req: super::image::MetaContainerRequest) -> ::ttrpc::Result<super::image::MetaContainerResponse> {
        Err(::ttrpc::Error::RpcStatus(::ttrpc::get_status(::ttrpc::Code::NOT_FOUND, "/grpc.Image/MetaContainer is not supported".to_string())))
    }
}

pub fn create_image(service: Arc<std::boxed::Box<dyn Image + Send + Sync>>) -> HashMap <String, Box<dyn ::ttrpc::MethodHandler + Send + Sync>> {
    let mut methods = HashMap::new();

    methods.insert("/grpc.Image/PullImage".to_string(),
                    std::boxed::Box::new(PullImageMethod{service: service.clone()}) as std::boxed::Box<dyn ::ttrpc::MethodHandler + Send + Sync>);

    methods.insert("/grpc.Image/MetaContainer".to_string(),
                    std::boxed::Box::new(MetaContainerMethod{service: service.clone()}) as std::boxed::Box<dyn ::ttrpc::MethodHandler + Send + Sync>);

    methods
}
