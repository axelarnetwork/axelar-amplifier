use std::net::{IpAddr, SocketAddr};

use ampd_proto::blockchain_service_server::BlockchainServiceServer;
use ampd_proto::crypto_service_server::CryptoServiceServer;
use axelar_wasm_std::nonempty;
use error_stack::Result;
use report::{ErrorExt, LoggableError};
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use tonic::transport;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::trace;
use tracing::info;
use typed_builder::TypedBuilder;
use valuable::Valuable;

use crate::{broadcaster_v2, cosmos, event_sub};

mod blockchain_service;
mod crypto_service;
mod error;
mod reqs;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to start the gRPC server")]
    Transport(#[from] transport::Error),
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Config {
    pub ip_addr: IpAddr,
    pub port: u16,
    pub concurrency_limit: nonempty::Usize,
    pub concurrency_limit_per_connection: nonempty::Usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ip_addr: "127.0.0.1".parse().expect("default IP must be valid"),
            port: 9090,
            concurrency_limit: 1024
                .try_into()
                .expect("default concurrency limit must be valid"),
            concurrency_limit_per_connection: 32
                .try_into()
                .expect("default concurrency limit per connection must be valid"),
        }
    }
}

pub fn deserialize_config<'de, D>(deserializer: D) -> std::result::Result<Config, D::Error>
where
    D: Deserializer<'de>,
{
    let config: Config = Deserialize::deserialize(deserializer)?;

    if config.concurrency_limit < config.concurrency_limit_per_connection {
        return Err(de::Error::custom(
            "concurrency_limit must be >= concurrency_limit_per_connection",
        ));
    }

    Ok(config)
}

#[derive(TypedBuilder)]
pub struct Server {
    config: Config,
    event_sub: event_sub::EventSubscriber,
    msg_queue_client: broadcaster_v2::MsgQueueClient<cosmos::CosmosGrpcClient>,
}

impl Server {
    pub async fn run(self, token: CancellationToken) -> Result<(), Error> {
        let addr = SocketAddr::new(self.config.ip_addr, self.config.port);
        let trace_layer = trace::TraceLayer::new_for_grpc()
            .make_span_with(trace::DefaultMakeSpan::new().level(tracing::Level::INFO))
            .on_request(trace::DefaultOnRequest::new().level(tracing::Level::INFO))
            .on_response(trace::DefaultOnResponse::new().level(tracing::Level::INFO))
            .on_failure(trace::DefaultOnFailure::new().level(tracing::Level::ERROR));
        let router = transport::Server::builder()
            .layer(trace_layer)
            .layer(ConcurrencyLimitLayer::new(
                self.config.concurrency_limit.into(),
            ))
            .concurrency_limit_per_connection(self.config.concurrency_limit_per_connection.into())
            .add_service(BlockchainServiceServer::new(
                blockchain_service::Service::builder()
                    .event_sub(self.event_sub)
                    .msg_queue_client(self.msg_queue_client)
                    .build(),
            ))
            .add_service(CryptoServiceServer::new(crypto_service::Service::new()));

        info!(addr = addr.to_string(), "gRPC server started");

        router
            .serve_with_shutdown(addr, token.cancelled_owned())
            .await
            .map_err(ErrorExt::into_report)
            .inspect(|_| {
                info!("gRPC server stopped");
            })
            .inspect_err(|err| {
                info!(
                    err = LoggableError::from(err).as_value(),
                    "gRPC server failed"
                );
            })
    }
}
