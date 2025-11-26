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
use tracing::{info, Level};

use crate::error::Error;

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum HandlerType {
    GmpVoting,
    EventVerification,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct EvmHandlerConfig {
    #[serde(deserialize_with = "Url::deserialize_sensitive")]
    rpc_url: Url,
    #[serde(with = "humantime_serde")]
    #[serde(default = "default_rpc_timeout")]
    rpc_timeout: Duration,
    #[serde(default)]
    finalization: Finalization,
    // confirmation height is only used for event verification, and only required if finalization is ConfirmationHeight
    // can be omitted for GMP voting, or if finalization is RPCFinalizedBlock
    confirmation_height: Option<u64>,
    handlers_to_run: Vec<HandlerType>,
}

fn default_rpc_timeout() -> Duration {
    Duration::from_secs(3)
}

fn build_gmp_handler(
    runtime: &HandlerRuntime,
    chain_name: ChainName,
    config: &EvmHandlerConfig,
) -> Result<gmp::Handler<json_rpc::Client<Http>>, Error> {
    let rpc_client = json_rpc::Client::new_http(
        config.rpc_url.clone(),
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
        .finalizer_type(config.finalization.clone())
        .rpc_client(rpc_client)
        .monitoring_client(runtime.monitoring_client.clone())
        .build();

    Ok(handler)
}

fn build_event_verifier_handler(
    runtime: &HandlerRuntime,
    chain_name: ChainName,
    config: &EvmHandlerConfig,
) -> Result<event_verifier::Handler<json_rpc::Client<Http>>, Error> {
    let rpc_client = json_rpc::Client::new_http(
        config.rpc_url.clone(),
        reqwest::ClientBuilder::new()
            .connect_timeout(config.rpc_timeout)
            .timeout(config.rpc_timeout)
            .build()
            .change_context(Error::HandlerStart)?,
        runtime.monitoring_client.clone(),
        chain_name.clone(),
    );

    let confirmation_height = match config.finalization {
        Finalization::ConfirmationHeight => config
            .confirmation_height
            .ok_or(Error::MissingConfirmationHeight)?,
        // This finalizer type won't actually use the confirmation height field
        Finalization::RPCFinalizedBlock => config.confirmation_height.unwrap_or(1),
    };

    let handler = event_verifier::Handler::builder()
        .verifier(runtime.verifier.clone())
        .event_verifier_contract(
            runtime
                .contracts
                .event_verifier
                .clone()
                .ok_or(Error::EventVerifierContractNotFound)?,
        )
        .chain(chain_name)
        .finalizer_type(config.finalization.clone())
        .confirmation_height(confirmation_height)
        .rpc_client(rpc_client)
        .monitoring_client(runtime.monitoring_client.clone())
        .build();

    Ok(handler)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    ampd_handlers::tracing::init_tracing(Level::INFO);

    let base_config = config::Config::from_default_sources().change_context(Error::HandlerStart)?;

    let handler_config = config::Config::builder()
        .add_file_source("evm-handler-config.toml")
        .add_env_source("AMPD_EVM_HANDLER")
        .build::<EvmHandlerConfig>()
        .change_context(Error::HandlerStart)?;

    if handler_config.handlers_to_run.is_empty() {
        return Err(Error::HandlerStart)
            .attach_printable("No handlers configured. The 'handlers_to_run' array must contain at least one handler (gmp_voting or event_verification)");
    }

    let token = CancellationToken::new();

    // Create a single shared runtime for both handlers
    let runtime = HandlerRuntime::start(&base_config, token.clone())
        .await
        .change_context(Error::HandlerStart)?;

    let mut task_group = TaskGroup::new("evm-handlers");

    if handler_config
        .handlers_to_run
        .contains(&HandlerType::GmpVoting)
    {
        let runtime = runtime.clone();
        let base_config_clone = base_config.clone();
        let handler_config_clone = handler_config.clone();
        let gmp_task = CancellableTask::create(move |token| async move {
            let handler = build_gmp_handler(
                &runtime,
                base_config_clone.chain_name.clone(),
                &handler_config_clone,
            )?;

            runtime
                .run_handler(handler, base_config_clone, token)
                .await
                .change_context(Error::HandlerTask)
        });
        task_group = task_group.add_task("gmp-voting-handler", gmp_task);
        info!("GMP voting handler configured and will be started");
    }

    if handler_config
        .handlers_to_run
        .contains(&HandlerType::EventVerification)
    {
        let runtime = runtime.clone();
        let base_config_clone = base_config.clone();
        let handler_config_clone = handler_config.clone();
        let event_verifier_task = CancellableTask::create(move |token| async move {
            let handler = build_event_verifier_handler(
                &runtime,
                base_config_clone.chain_name.clone(),
                &handler_config_clone,
            )?;

            runtime
                .run_handler(handler, base_config_clone, token)
                .await
                .change_context(Error::HandlerTask)
        });
        task_group = task_group.add_task("event-verifier-handler", event_verifier_task);
        info!("Event verifier handler configured and will be started");
    }

    task_group
        .run(token)
        .await
        .change_context(Error::TaskGroup)?;

    Ok(())
}
