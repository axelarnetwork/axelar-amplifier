mod error;
mod handler;

use std::time::Duration;

use ampd::asyncutil::task::{CancellableTask, TaskGroup};
use ampd::url::Url;
use ampd::xrpl;
use ampd_handlers::Args;
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
struct XrplHandlerConfig {
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
    config: XrplHandlerConfig,
) -> Result<Handler<xrpl::json_rpc::Client>, Error> {
    let xrpl_http_client = xrpl_http_client::Client::builder()
        .base_url(config.rpc_url.as_str())
        .http_client(
            reqwest::ClientBuilder::new()
                .connect_timeout(config.rpc_timeout)
                .timeout(config.rpc_timeout)
                .build()
                .change_context(Error::HandlerStart)?,
        )
        .build();

    let rpc_client = xrpl::json_rpc::Client::new(
        xrpl_http_client,
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

fn voting_handler_task(
    runtime: HandlerRuntime,
    base_config: config::Config,
    handler_config: XrplHandlerConfig,
) -> CancellableTask<Result<(), Error>> {
    CancellableTask::create(move |token| async move {
        let handler = build_handler(&runtime, base_config.chain_name.clone(), handler_config)?;

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

    let handler_config = config::builder::<XrplHandlerConfig>()
        .add_file_source(args.config_dir.join("xrpl-handler-config.toml"))
        .add_env_source("AMPD_XRPL_HANDLER")
        .build()
        .change_context(Error::HandlerStart)?;

    let token = CancellationToken::new();

    let runtime = HandlerRuntime::start(&base_config, token.clone())
        .await
        .change_context(Error::HandlerStart)?;

    let mut task_group = TaskGroup::new("xrpl-handlers");

    task_group = task_group.add_task(
        "voting-handler",
        voting_handler_task(runtime.clone(), base_config.clone(), handler_config.clone()),
    );

    task_group
        .run(token)
        .await
        .change_context(Error::TaskGroup)?;

    Ok(())
}
