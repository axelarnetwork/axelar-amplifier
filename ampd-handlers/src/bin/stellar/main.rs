mod error;
mod handler;

use ampd::asyncutil::task::{CancellableTask, TaskGroup};
use ampd::stellar::rpc_client::Client;
use ampd::url::Url;
use ampd_handlers::tracing::init_tracing;
use ampd_handlers::{multisig, Args};
use ampd_sdk::config;
use ampd_sdk::runtime::HandlerRuntime;
use axelar_wasm_std::chain::ChainName;
use clap::Parser;
#[cfg(debug_assertions)]
use dotenv_flow::dotenv_flow;
use error_stack::{Result, ResultExt};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use tracing::Level;

use crate::error::Error;
use crate::handler::Handler;

#[derive(Clone, Debug, Deserialize, Serialize)]
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

fn voting_handler_task(
    runtime: HandlerRuntime,
    base_config: config::Config,
    handler_config: StellarHandlerConfig,
) -> CancellableTask<Result<(), Error>> {
    CancellableTask::create(move |token| async move {
        let handler = build_handler(&runtime, base_config.chain_name.clone(), handler_config)?;

        runtime
            .run_handler(handler, base_config, token)
            .await
            .change_context(Error::HandlerTask)
    })
}

fn multisig_handler_task(
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

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Load environment variables from .env files in debug builds
    #[cfg(debug_assertions)]
    dotenv_flow().ok();

    let args: Args = Args::parse();
    init_tracing(Level::INFO);

    let base_config = config::Config::from_default_sources(args.config_dir.clone())
        .change_context(Error::HandlerStart)?;

    let handler_config = config::builder::<StellarHandlerConfig>()
        .add_file_source(args.config_dir.join("stellar-handler-config.toml"))
        .add_env_source("AMPD_STELLAR_HANDLER")
        .build()
        .change_context(Error::HandlerStart)?;

    let token = CancellationToken::new();

    let runtime = HandlerRuntime::start(&base_config, token.clone())
        .await
        .change_context(Error::HandlerStart)?;

    let mut task_group = TaskGroup::new("stellar-handlers");

    task_group = task_group.add_task(
        "voting-handler",
        voting_handler_task(runtime.clone(), base_config.clone(), handler_config.clone()),
    );
    task_group = task_group.add_task(
        "multisig-handler",
        multisig_handler_task(runtime, base_config),
    );

    task_group
        .run(token)
        .await
        .change_context(Error::TaskGroup)?;

    Ok(())
}
