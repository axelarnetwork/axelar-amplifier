mod error;
mod handler;

use std::time::Duration;

use ampd::evm::finalizer::Finalization;
use ampd::url::Url;
use ampd::{json_rpc, monitoring};
use ampd_sdk::config::Config;
use ampd_sdk::event::event_handler::HandlerTask;
use ampd_sdk::future::RetryPolicy;
use ampd_sdk::grpc::client::{Client, GrpcClient};
use ampd_sdk::grpc::connection_pool::ConnectionPool;
use error_stack::{Result, ResultExt};
use serde::{Deserialize, Serialize};
use tokio::signal::unix::{signal, SignalKind};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::error::Error;
use crate::handler::Handler;

const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Deserialize, Serialize)]
struct EvmHandlerConfig {
    #[serde(flatten)]
    base_config: Config,
    #[serde(deserialize_with = "Url::deserialize_sensitive")]
    #[serde(default = "default_rpc_url")]
    rpc_url: Url,
}

fn default_rpc_url() -> Url {
    Url::new_sensitive("https://testnet.evm.nodes.onflow.org").expect("URL should be valid")
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let config = Config::builder()
        .add_file_source("config.toml")
        .add_env_source("AMPD_HANDLERS")
        .build_generic::<EvmHandlerConfig>()
        .change_context(Error::Config)?;
    let token = CancellationToken::new();

    let (pool, handle) = ConnectionPool::new(config.base_config.ampd_url);
    let pool_token = token.clone();
    tokio::spawn(async move {
        let _ = pool.run(pool_token).await;
    });

    let mut client = GrpcClient::new(handle);
    let contracts = client
        .contracts(config.base_config.chain_name.clone())
        .await
        .change_context(Error::Grpc)?;
    let verifier = client.address().await.change_context(Error::Grpc)?;

    let (monitoring_server, monitoring_client) =
        monitoring::Server::new(monitoring::Config::Disabled)
            .expect("failed to create monitoring server"); // TODO: make this configurable
    let monitoring_token = token.clone();
    tokio::spawn(async move {
        let _ = monitoring_server.run(monitoring_token).await;
    });

    let rpc_client = json_rpc::Client::new_http(
        config.rpc_url,
        reqwest::ClientBuilder::new()
            .connect_timeout(DEFAULT_RPC_TIMEOUT) // TODO: make this configurable
            .timeout(DEFAULT_RPC_TIMEOUT)
            .build()
            .change_context(Error::RpcConnection)?,
        monitoring_client.clone(),
        config.base_config.chain_name.clone(),
    );

    let handler = Handler::builder()
        .verifier(verifier)
        .voting_verifier_contract(contracts.voting_verifier)
        .chain(config.base_config.chain_name)
        .finalizer_type(Finalization::RPCFinalizedBlock) // TODO: make this configurable
        .rpc_client(rpc_client)
        .monitoring_client(monitoring_client)
        .build();

    let task = HandlerTask::builder()
        .handler(handler)
        .config(config.base_config.event_handler)
        .handler_retry_policy(RetryPolicy::RepeatConstant {
            sleep: Duration::from_secs(1),
            max_attempts: 3,
        })
        .build();

    let exit_token = token.clone();
    tokio::spawn(async move {
        let mut sigint = signal(SignalKind::interrupt()).expect("failed to capture SIGINT");
        let mut sigterm = signal(SignalKind::terminate()).expect("failed to capture SIGTERM");

        tokio::select! {
            _ = sigint.recv() => {},
            _ = sigterm.recv() => {},
        }

        info!("signal received, waiting for program to exit gracefully");

        exit_token.cancel();
    });

    task.run(&mut client, token)
        .await
        .change_context(Error::HandlerTask)?;

    Ok(())
}
