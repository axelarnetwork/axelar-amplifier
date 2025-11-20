mod error;
mod handler;

use ampd::stellar::rpc_client::Client;
use ampd::url::Url;
use ampd_handlers::tracing::init_tracing;
use ampd_sdk::config;
use ampd_sdk::runtime::HandlerRuntime;
use axelar_wasm_std::chain::ChainName;
#[cfg(debug_assertions)]
use dotenv::dotenv;
use error_stack::{Result, ResultExt};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use tracing::Level;

use crate::error::Error;
use crate::handler::Handler;

#[derive(Debug, Deserialize, Serialize)]
struct StellarHandlerConfig {
    #[serde(deserialize_with = "Url::deserialize_sensitive")]
    rpc_url: Url,
}

fn build_handler(
    runtime: &HandlerRuntime,
    chain_name: ChainName,
    config: StellarHandlerConfig,
) -> Result<Handler<Client>, Error> {
    let rpc_client = Client::new(
        config.rpc_url,
        runtime.monitoring_client.clone(),
        chain_name.clone(),
    )
    .change_context(Error::HandlerStart)?;

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
    dotenv().ok();

    init_tracing(Level::INFO);

    let base_config = config::Config::from_default_sources().change_context(Error::HandlerStart)?;

    let handler_config = config::Config::builder()
        .add_file_source("stellar-handler-config.toml")
        .add_env_source("AMPD_STELLAR_HANDLER")
        .build::<StellarHandlerConfig>()
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
