use std::fmt;
use std::fmt::Debug;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

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
use tracing::{info, instrument};
use typed_builder::TypedBuilder;
use valuable::Valuable;

use crate::types::debug::REDACTED_VALUE;
use crate::{broadcast, cosmos, event_sub, tofnd};

mod blockchain_service;
mod config;
mod crypto_service;
mod reqs;
mod status;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Transport(#[from] transport::Error),
}

#[derive(Serialize, Deserialize, PartialEq)]
pub struct Config {
    /// IP address on which the gRPC server will listen
    pub ip_addr: IpAddr,
    /// Port number on which the gRPC server will listen
    pub port: u16,
    /// Maximum number of concurrent requests the server can handle globally across all connections
    /// This applies server-wide concurrency limiting to prevent resource exhaustion
    /// Requests beyond this limit will be queued until processing slots become available
    pub global_concurrency_limit: nonempty::Usize,
    /// Maximum number of concurrent requests the server can handle per client connection
    /// Helps prevent a single client from monopolizing server resources
    /// Must be less than or equal to global_concurrency_limit
    pub concurrency_limit_per_connection: nonempty::Usize,
    /// Maximum time allowed for processing a single request before timing out
    /// Applies to all gRPC method calls
    /// Uses humantime_serde for parsing human-readable duration formats in configuration files
    #[serde(with = "humantime_serde")]
    pub request_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ip_addr: "127.0.0.1".parse().expect("default IP must be valid"),
            port: 9090,
            global_concurrency_limit: 1024
                .try_into()
                .expect("default concurrency limit must be valid"),
            concurrency_limit_per_connection: 32
                .try_into()
                .expect("default concurrency limit per connection must be valid"),
            request_timeout: Duration::from_secs(30),
        }
    }
}

impl Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("ip_addr", &REDACTED_VALUE)
            .field("port", &REDACTED_VALUE)
            .field("global_concurrency_limit", &self.global_concurrency_limit)
            .field(
                "concurrency_limit_per_connection",
                &self.concurrency_limit_per_connection,
            )
            .field("request_timeout", &self.request_timeout)
            .finish()
    }
}

pub fn deserialize_config<'de, D>(deserializer: D) -> std::result::Result<Config, D::Error>
where
    D: Deserializer<'de>,
{
    let config: Config = Deserialize::deserialize(deserializer)?;

    if config.global_concurrency_limit < config.concurrency_limit_per_connection {
        return Err(de::Error::custom(
            "concurrency_limit must be >= concurrency_limit_per_connection",
        ));
    }

    Ok(config)
}

#[derive(Debug, TypedBuilder)]
pub struct Server {
    config: Config,
    event_sub: event_sub::EventSubscriber,
    msg_queue_client: broadcast::MsgQueueClient<cosmos::CosmosGrpcClient>,
    cosmos_grpc_client: cosmos::CosmosGrpcClient,
    multisig_client: tofnd::MultisigClient,
}

impl Server {
    #[instrument]
    pub async fn run(self, token: CancellationToken) -> Result<(), Error> {
        let addr = SocketAddr::new(self.config.ip_addr, self.config.port);
        // Configure tracing middleware for gRPC server requests
        // This creates structured logs for request/response monitoring
        let trace_layer = trace::TraceLayer::new_for_grpc()
            // Configure how spans are created for each request
            // This adds a new trace span at INFO level containing method info
            // Example span: grpc_request{method="/amplifier.blockchain.BlockchainService/broadcast"}
            .make_span_with(trace::DefaultMakeSpan::new().level(tracing::Level::INFO))
            // Configure what's logged when a request is received
            // This logs at INFO level when a request starts processing
            // Example: INFO grpc_request{method="..."}: started processing request
            .on_request(trace::DefaultOnRequest::new().level(tracing::Level::INFO))
            // Configure what's logged when a response is sent
            // This logs at INFO level when a request completes successfully
            // Example: INFO grpc_request{method="..."}: finished processing request latency=10ms status=200
            .on_response(trace::DefaultOnResponse::new().level(tracing::Level::INFO))
            // Configure what's logged when a request fails with an error
            // This logs at ERROR level with status code and error details
            // Example: ERROR grpc_request{method="..."}: failed to process request latency=5ms status=INVALID_ARGUMENT code=3 message="empty broadcast message"
            .on_failure(trace::DefaultOnFailure::new().level(tracing::Level::ERROR));
        let router = transport::Server::builder()
            .timeout(self.config.request_timeout)
            .layer(trace_layer)
            .layer(ConcurrencyLimitLayer::new(
                self.config.global_concurrency_limit.into(),
            ))
            .concurrency_limit_per_connection(self.config.concurrency_limit_per_connection.into())
            .add_service(BlockchainServiceServer::new(
                blockchain_service::Service::builder()
                    .event_sub(self.event_sub)
                    .msg_queue_client(self.msg_queue_client)
                    .cosmos_client(self.cosmos_grpc_client)
                    .build(),
            ))
            .add_service(CryptoServiceServer::new(crypto_service::Service::from(
                self.multisig_client,
            )));

        info!(%addr, "gRPC server started");

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
