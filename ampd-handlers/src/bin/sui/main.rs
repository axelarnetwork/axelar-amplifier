mod error;
mod handler;

use std::time::Duration;

use ampd::json_rpc;
use ampd::url::Url;
use ampd_handlers::tracing::init_tracing;
use ampd_sdk::config;
use ampd_sdk::runtime::HandlerRuntime;
use axelar_wasm_std::chain::ChainName;
#[cfg(debug_assertions)]
use dotenv_flow::dotenv_flow;
use error_stack::{Result, ResultExt};
use ethers_providers::Http;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use tracing::Level;
use tracing_core::LevelFilter;
use tracing_error::ErrorLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use crate::error::Error;
use crate::handler::Handler;

#[derive(Debug, Deserialize, Serialize)]
struct SuiHandlerConfig {
    #[serde(deserialize_with = "Url::deserialize_sensitive")]
    rpc_url: Url,
    #[serde(with = "humantime_serde")]
    #[serde(default = "default_rpc_timeout")]
    rpc_timeout: Duration,
}

fn default_rpc_timeout() -> Duration {
    Duration::from_secs(3)
}

fn build_handler(
    runtime: &HandlerRuntime,
    chain_name: ChainName,
    config: SuiHandlerConfig,
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
        .rpc_client(rpc_client)
        .monitoring_client(runtime.monitoring_client.clone())
        .build();

    Ok(handler)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    #[cfg(debug_assertions)]
    dotenv_flow().ok();

    init_tracing(Level::INFO);

    let base_config = config::Config::from_default_sources().change_context(Error::HandlerStart)?;
    let handler_config = config::Config::builder()
        .add_file_source("sui-handler-config.toml")
        .add_env_source("AMPD_SUI_HANDLER")
        .build::<SuiHandlerConfig>()
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
