use std::net::{IpAddr, SocketAddr};

use ampd_proto::blockchain_service_server::BlockchainServiceServer;
use ampd_proto::crypto_service_server::CryptoServiceServer;
use error_stack::Result;
use report::ErrorExt;
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use tonic::transport;
use tower::layer::util::{Identity, Stack};
use tower::limit::ConcurrencyLimitLayer;

mod blockchain_service;
mod crypto_service;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to start the gRPC server")]
    Transport(#[from] transport::Error),
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Config {
    pub ip_addr: IpAddr,
    pub port: u16,
    pub concurrency_limit: usize,
    pub concurrency_limit_per_connection: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ip_addr: "127.0.0.1".parse().expect("default IP must be valid"),
            port: 9090,
            concurrency_limit: 1024,
            concurrency_limit_per_connection: 32,
        }
    }
}

pub fn deserialize_config<'de, D>(deserializer: D) -> std::result::Result<Config, D::Error>
where
    D: Deserializer<'de>,
{
    let config: Config = Deserialize::deserialize(deserializer)?;

    if config.concurrency_limit == 0 {
        return Err(de::Error::custom("concurrency_limit must be > 0"));
    }

    if config.concurrency_limit_per_connection == 0 {
        return Err(de::Error::custom(
            "concurrency_limit_per_connection must be > 0",
        ));
    }

    if config.concurrency_limit < config.concurrency_limit_per_connection {
        return Err(de::Error::custom(
            "concurrency_limit must be >= concurrency_limit_per_connection",
        ));
    }

    Ok(config)
}

pub struct Server {
    addr: SocketAddr,
    router: transport::server::Router<Stack<ConcurrencyLimitLayer, Identity>>,
}

impl Server {
    pub fn new(config: &Config) -> Self {
        Self {
            addr: SocketAddr::new(config.ip_addr, config.port),
            router: transport::Server::builder()
                .layer(ConcurrencyLimitLayer::new(config.concurrency_limit))
                .concurrency_limit_per_connection(config.concurrency_limit_per_connection)
                .add_service(BlockchainServiceServer::new(
                    blockchain_service::Service::new(),
                ))
                .add_service(CryptoServiceServer::new(crypto_service::Service::new())),
        }
    }

    pub async fn run(self, token: CancellationToken) -> Result<(), Error> {
        self.router
            .serve_with_shutdown(self.addr, token.cancelled_owned())
            .await
            .map_err(ErrorExt::into_report)
    }
}
