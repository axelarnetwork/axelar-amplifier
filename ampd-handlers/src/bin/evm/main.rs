mod common;
mod error;
mod handler;
mod messages_handler;
mod verifier_set_handler;

use std::time::Duration;

use ampd::evm::finalizer::Finalization;
use ampd::json_rpc;
use ampd::url::Url;
use ampd_sdk::config;
use ampd_sdk::runtime::HandlerRuntime;
use axelar_wasm_std::chain::ChainName;
#[cfg(debug_assertions)]
use dotenv::dotenv;
use error_stack::{Result, ResultExt};
use ethers_providers::Http;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use tracing::Level;

use crate::error::Error;
use crate::handler::Handler;

#[derive(Debug, Deserialize, Serialize)]
struct EvmHandlerConfig {
    #[serde(deserialize_with = "Url::deserialize_sensitive")]
    rpc_url: Url,
    #[serde(with = "humantime_serde")]
    #[serde(default = "default_rpc_timeout")]
    rpc_timeout: Duration,
    #[serde(default)]
    finalization: Finalization,
}

fn default_rpc_timeout() -> Duration {
    Duration::from_secs(3)
}

fn build_handler(
    runtime: &HandlerRuntime,
    chain_name: ChainName,
    config: EvmHandlerConfig,
) -> Result<Handler<json_rpc::Client<Http>>, Error> {
    let rpc_client = json_rpc::Client::new_http(
        config.rpc_url,
        reqwest::ClientBuilder::new()
            .connect_timeout(config.rpc_timeout)
            .timeout(config.rpc_timeout)
            .build()
            .change_context(Error::HandlerStart)?,
        runtime.monitoring_client.clone(),
        chain_name.clone(),
    );

    let handler = Handler::builder()
        .verifier(runtime.verifier.clone())
        .voting_verifier_contract(runtime.contracts.voting_verifier.clone())
        .chain(chain_name)
        .finalizer_type(config.finalization)
        .rpc_client(rpc_client)
        .monitoring_client(runtime.monitoring_client.clone())
        .build();

    Ok(handler)
}

fn init_tracing(max_level: Level) {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(max_level)
            .finish(),
    )
    .expect("failed to set global default tracing subscriber");
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    #[cfg(debug_assertions)]
    dotenv().ok();

    init_tracing(Level::INFO);

    let base_config = config::Config::from_default_sources().change_context(Error::HandlerStart)?;
    let handler_config = config::Config::builder()
        .add_file_source("evm-handler-config.toml")
        .add_env_source("EVM_HANDLER")
        .build::<EvmHandlerConfig>()
        .change_context(Error::HandlerStart)?;

    let token = CancellationToken::new();

    let runtime = HandlerRuntime::start(&base_config, token.clone())
        .await
        .change_context(Error::HandlerStart)?;

    let handler = build_handler(&runtime, base_config.chain_name.clone(), handler_config)?;

    runtime
        .run_handler(handler, base_config, token)
        .await
        .change_context(Error::HandlerTask)?;

    Ok(())
}
