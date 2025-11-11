mod error;
mod event_verifier;
mod gmp;

use std::time::Duration;

use ampd::asyncutil::task::{CancellableTask, TaskGroup};
use ampd::evm::finalizer::Finalization;
use ampd::json_rpc;
use ampd::url::Url;
use ampd_sdk::config;
use ampd_sdk::runtime::HandlerRuntime;
use axelar_wasm_std::chain::ChainName;
use error_stack::{Result, ResultExt};
use ethers_providers::Http;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn, Level};
use tracing_error::ErrorLayer;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use crate::error::Error;

#[derive(Debug, Deserialize, Serialize)]
struct EvmGmpHandlerConfig {
    #[serde(deserialize_with = "Url::deserialize_sensitive")]
    rpc_url: Url,
    #[serde(with = "humantime_serde")]
    #[serde(default = "default_rpc_timeout")]
    rpc_timeout: Duration,
    #[serde(default)]
    finalization: Finalization,
}

#[derive(Debug, Deserialize, Serialize)]
struct EvmEventVerifierHandlerConfig {
    #[serde(deserialize_with = "Url::deserialize_sensitive")]
    rpc_url: Url,
    #[serde(with = "humantime_serde")]
    #[serde(default = "default_rpc_timeout")]
    rpc_timeout: Duration,
    #[serde(default)]
    finalization: Finalization,
    confirmation_height: Option<u64>,
}

fn default_rpc_timeout() -> Duration {
    Duration::from_secs(3)
}

fn build_gmp_handler(
    runtime: &HandlerRuntime,
    chain_name: ChainName,
    config: EvmGmpHandlerConfig,
) -> Result<gmp::Handler<json_rpc::Client<Http>>, Error> {
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

    let handler = gmp::Handler::builder()
        .verifier(runtime.verifier.clone())
        .voting_verifier_contract(runtime.contracts.voting_verifier.clone())
        .chain(chain_name)
        .finalizer_type(config.finalization)
        .rpc_client(rpc_client)
        .monitoring_client(runtime.monitoring_client.clone())
        .build();

    Ok(handler)
}

fn build_event_verifier_handler(
    runtime: &HandlerRuntime,
    chain_name: ChainName,
    config: EvmEventVerifierHandlerConfig,
) -> Result<event_verifier::Handler<json_rpc::Client<Http>>, Error> {
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

    let confirmation_height = match config.finalization {
        Finalization::ConfirmationHeight => {
            config.confirmation_height.ok_or(Error::HandlerStart)?
        }
        // This finalizer type won't actually use the confirmation height field
        Finalization::RPCFinalizedBlock => config.confirmation_height.unwrap_or(1),
    };

    let handler = event_verifier::Handler::builder()
        .verifier(runtime.verifier.clone())
        .event_verifier_contract(runtime.contracts.event_verifier.clone().ok_or(Error::EventVerifierContractNotFound)?)
        .chain(chain_name)
        .finalizer_type(config.finalization)
        .confirmation_height(confirmation_height)
        .rpc_client(rpc_client)
        .monitoring_client(runtime.monitoring_client.clone())
        .build();

    Ok(handler)
}

fn init_tracing(max_level: Level) {
    let error_layer = ErrorLayer::default();
    let filter_layer = EnvFilter::builder()
        .with_default_directive(LevelFilter::from_level(max_level).into())
        .from_env_lossy();
    let fmt_layer = tracing_subscriber::fmt::layer().json().flatten_event(true);

    tracing_subscriber::registry()
        .with(error_layer)
        .with(filter_layer)
        .with(fmt_layer)
        .init();
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    init_tracing(Level::INFO);

    let base_config = config::Config::from_default_sources().change_context(Error::HandlerStart)?;

    let gmp_handler_config = config::Config::builder()
        .add_file_source("evm-handler-config.toml")
        .add_env_source("AMPD_EVM_HANDLER")
        .build::<EvmGmpHandlerConfig>()
        .ok();

    let event_verifier_handler_config = config::Config::builder()
        .add_file_source("evm-event-verifier-handler-config.toml")
        .add_env_source("AMPD_EVM_EVENT_VERIFIER_HANDLER")
        .build::<EvmEventVerifierHandlerConfig>()
        .ok();

    // Error if no handlers are configured
    if gmp_handler_config.is_none() && event_verifier_handler_config.is_none() {
        return Err(Error::HandlerStart)
            .attach_printable("No handler configurations found. At least one of evm-handler-config.toml or evm-event-verifier-handler-config.toml must be present");
    }

    let token = CancellationToken::new();

    // Create a single shared runtime for both handlers
    let runtime = HandlerRuntime::start(&base_config, token.clone())
        .await
        .change_context(Error::HandlerStart)?;

    let mut task_group = TaskGroup::new("evm-handlers");

    if let Some(gmp_handler_config) = gmp_handler_config {
        let runtime = runtime.clone();
        let base_config_clone = base_config.clone();
        let gmp_task = CancellableTask::create(move |token| async move {
            let handler = build_gmp_handler(
                &runtime,
                base_config_clone.chain_name.clone(),
                gmp_handler_config,
            )?;

            runtime
                .run_handler(handler, base_config_clone, token)
                .await
                .change_context(Error::HandlerTask)
        });
        task_group = task_group.add_task("gmp-handler", gmp_task);
        info!("GMP handler configured and will be started");
    } else {
        warn!("GMP handler config not found (evm-handler-config.toml), GMP handler will not run");
    }

    // Build event verifier handler task if config is present
    if let Some(event_verifier_handler_config) = event_verifier_handler_config {
        let runtime = runtime.clone();
        let base_config_clone = base_config.clone();
        let event_verifier_task = CancellableTask::create(move |token| async move {
            let handler = build_event_verifier_handler(
                &runtime,
                base_config_clone.chain_name.clone(),
                event_verifier_handler_config,
            )?;

            runtime
                .run_handler(handler, base_config_clone, token)
                .await
                .change_context(Error::HandlerTask)
        });
        task_group = task_group.add_task("event-verifier-handler", event_verifier_task);
        info!("Event verifier handler configured and will be started");
    } else {
        warn!("Event verifier handler config not found (evm-event-verifier-handler-config.toml), event verifier handler will not run");
    }

    // Run configured handlers concurrently using TaskGroup
    task_group
        .run(token)
        .await
        .change_context(Error::TaskGroup)?;

    Ok(())
}
