mod error;
mod event_verifier;
mod gmp;

use std::time::Duration;

use ampd::asyncutil::task::{CancellableTask, TaskGroup};
use ampd::json_rpc;
use ampd::url::Url;
use ampd_handlers::evm::finalizer::{pick, Finalization};
use ampd_handlers::evm::json_rpc::EthereumClient;
use ampd_handlers::{multisig, Args};
use ampd_sdk::config;
use ampd_sdk::runtime::HandlerRuntime;
use axelar_wasm_std::chain::ChainName;
use clap::Parser;
#[cfg(debug_assertions)]
use dotenv_flow::dotenv_flow;
use error_stack::{Result, ResultExt};
use ethers_providers::Http;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use tracing::{info, Level};

use crate::error::Error;

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
    // can be omitted for GMP handler, or if finalization is RPCFinalizedBlock
    confirmation_height: Option<u64>,
    #[serde(default = "default_gmp_handler_enabled")]
    gmp_handler_enabled: bool,
    #[serde(default)]
    event_verifier_handler_enabled: bool,
}

fn default_gmp_handler_enabled() -> bool {
    true
}

fn default_rpc_timeout() -> Duration {
    Duration::from_secs(3)
}

async fn check_finalizer<C>(
    chain_name: &ChainName,
    finalization: &Finalization,
    rpc_client: &C,
) -> Result<(), Error>
where
    C: EthereumClient + Send + Sync,
{
    let _ = pick(finalization, rpc_client, 0)
        .latest_finalized_block_height()
        .await
        .change_context_lazy(|| Error::InvalidFinalizerType(chain_name.to_owned()))?;

    Ok(())
}

async fn build_gmp_voting_handler(
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

    check_finalizer(&chain_name, &config.finalization, &rpc_client).await?;

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

fn gmp_voting_handler_task(
    runtime: HandlerRuntime,
    base_config: config::Config,
    handler_config: EvmHandlerConfig,
) -> CancellableTask<Result<(), Error>> {
    CancellableTask::create(move |token| async move {
        let handler =
            build_gmp_voting_handler(&runtime, base_config.chain_name.clone(), &handler_config)
                .await?;

        runtime
            .run_handler(handler, base_config, token)
            .await
            .change_context(Error::HandlerTask)
    })
}

fn gmp_multisig_handler_task(
    runtime: HandlerRuntime,
    base_config: config::Config,
) -> CancellableTask<Result<(), Error>> {
    CancellableTask::create(move |token| async move {
        let handler = multisig::Handler::new(&runtime, base_config.chain_name.clone());

        runtime
            .run_handler(handler, base_config, token)
            .await
            .change_context(Error::HandlerTask)
    })
}

fn event_verifier_task(
    runtime: HandlerRuntime,
    base_config: config::Config,
    handler_config: EvmHandlerConfig,
) -> CancellableTask<Result<(), Error>> {
    CancellableTask::create(move |token| async move {
        let handler = build_event_verifier_handler(
            &runtime,
            base_config.chain_name.clone(),
            &handler_config,
        )?;

        runtime
            .run_handler(handler, base_config, token)
            .await
            .change_context(Error::HandlerTask)
    })
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Load environment variables from .env files in debug builds
    #[cfg(debug_assertions)]
    dotenv_flow().ok();

    let args: Args = Args::parse();
    ampd_handlers::tracing::init_tracing(Level::INFO);

    let base_config = config::Config::from_default_sources(args.config_dir.clone())
        .change_context(Error::HandlerStart)?;

    let handler_config = config::builder::<EvmHandlerConfig>()
        .add_file_source(args.config_dir.join("evm-handler-config.toml"))
        .add_env_source("AMPD_EVM_HANDLER")
        .build()
        .change_context(Error::HandlerStart)?;

    if !(handler_config.gmp_handler_enabled || handler_config.event_verifier_handler_enabled) {
        return Err(Error::HandlerStart)
            .attach_printable("No handlers configured. Either 'gmp_handler_enabled' or 'event_verifier_handler_enabled' must be true");
    }

    let token = CancellationToken::new();

    // Create a single shared runtime for all handlers
    let runtime = HandlerRuntime::start(&base_config, token.clone())
        .await
        .change_context(Error::HandlerStart)?;

    let mut task_group = TaskGroup::new("evm-handlers");

    if handler_config.gmp_handler_enabled {
        task_group = task_group.add_task(
            "gmp-voting-handler",
            gmp_voting_handler_task(runtime.clone(), base_config.clone(), handler_config.clone()),
        );

        task_group = task_group.add_task(
            "gmp-multisig-handler",
            gmp_multisig_handler_task(runtime.clone(), base_config.clone()),
        );

        info!("GMP voting and multisig handlers configured and will be started");
    }

    if handler_config.event_verifier_handler_enabled {
        task_group = task_group.add_task(
            "event-verifier-handler",
            event_verifier_task(runtime, base_config, handler_config),
        );
        info!("Event verifier handler configured and will be started");
    }

    task_group
        .run(token)
        .await
        .change_context(Error::TaskGroup)?;

    Ok(())
}
