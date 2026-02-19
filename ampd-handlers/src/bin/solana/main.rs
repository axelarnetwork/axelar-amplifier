mod config;
mod error;
mod handler;

use std::str::FromStr;

use ampd::asyncutil::task::{CancellableTask, TaskGroup};
use ampd_handlers::solana::Client;
use ampd_handlers::tracing::init_tracing;
use ampd_handlers::{multisig, Args};
use ampd_sdk::config as sdk_config;
use ampd_sdk::runtime::HandlerRuntime;
use axelar_wasm_std::chain::ChainName;
use clap::Parser;
#[cfg(debug_assertions)]
use dotenv_flow::dotenv_flow;
use error_stack::{Result, ResultExt};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use tokio_util::sync::CancellationToken;
use tracing::Level;

use crate::config::{parse_domain_separator, SolanaHandlerConfig};
use crate::error::Error;
use crate::handler::Handler;

async fn build_handler(
    runtime: &HandlerRuntime,
    chain_name: ChainName,
    config: SolanaHandlerConfig,
) -> Result<Handler<Client>, Error> {
    let rpc_client = Client::new(
        RpcClient::new_with_timeout(config.rpc_url.to_string(), config.rpc_timeout),
        runtime.monitoring_client.clone(),
        chain_name.clone(),
    );

    let gateway_address =
        Pubkey::from_str(&config.gateway_address).change_context(Error::GatewayAddress)?;

    let domain_separator = parse_domain_separator(&config.domain_separator)?;

    let handler = Handler::builder()
        .verifier(runtime.verifier.clone())
        .voting_verifier_contract(runtime.contracts.voting_verifier.clone())
        .chain(chain_name)
        .gateway_address(gateway_address)
        .domain_separator(domain_separator)
        .rpc_client(rpc_client)
        .monitoring_client(runtime.monitoring_client.clone())
        .build();

    Ok(handler)
}

fn voting_handler_task(
    runtime: HandlerRuntime,
    base_config: sdk_config::Config,
    handler_config: SolanaHandlerConfig,
) -> CancellableTask<Result<(), Error>> {
    CancellableTask::create(move |token| async move {
        let handler =
            build_handler(&runtime, base_config.chain_name.clone(), handler_config).await?;

        runtime
            .run_handler(handler, base_config, token)
            .await
            .change_context(Error::HandlerTask)
    })
}

fn multisig_handler_task(
    runtime: HandlerRuntime,
    base_config: sdk_config::Config,
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

    let base_config = sdk_config::Config::from_default_sources(args.config_dir.clone())
        .change_context(Error::HandlerStart)?;
    let handler_config = sdk_config::builder::<SolanaHandlerConfig>()
        .add_file_source(args.config_dir.join("solana-handler-config.toml"))
        .add_env_source("AMPD_SOLANA_HANDLER")
        .build()
        .change_context(Error::HandlerStart)?;

    let token = CancellationToken::new();

    let runtime = HandlerRuntime::start(&base_config, token.clone())
        .await
        .change_context(Error::HandlerStart)?;

    let mut task_group = TaskGroup::new("solana-handlers");

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
