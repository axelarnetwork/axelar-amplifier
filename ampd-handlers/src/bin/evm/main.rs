mod error;
mod handler;

use std::time::Duration;

use ampd::evm::finalizer::Finalization;
use ampd::json_rpc;
use ampd::url::Url;
use ampd_sdk::config;
use ampd_sdk::event::event_handler::HandlerTask;
use ampd_sdk::future::RetryPolicy;
use ampd_sdk::runtime::HandlerRuntime;
use axelar_wasm_std::chain::ChainName;
use error_stack::{Result, ResultExt};
use ethers_providers::Http;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::error::Error;
use crate::handler::Handler;

const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Deserialize, Serialize)]
struct EvmHandlerConfig {
    #[serde(deserialize_with = "Url::deserialize_sensitive")]
    #[serde(default = "default_rpc_url")]
    rpc_url: Url,
}

fn default_rpc_url() -> Url {
    Url::new_sensitive("https://testnet.evm.nodes.onflow.org").expect("URL should be valid")
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let base_config = config::Config::from_default_sources().change_context(Error::HandlerStart)?;
    let handler_config = config::Config::builder()
        .add_file_source("evm-handler-config.toml")
        .add_env_source("EVM_HANDLER")
        .build::<EvmHandlerConfig>()
        .change_context(Error::HandlerStart)?;

    let token = CancellationToken::new();

    let mut runtime = HandlerRuntime::start(base_config.clone(), token.clone())
        .await
        .change_context(Error::HandlerStart)?;

    let handler = build_handler(&runtime, base_config.chain_name, handler_config)?;

    let task = HandlerTask::builder()
        .handler(handler)
        .config(base_config.event_handler)
        .handler_retry_policy(RetryPolicy::RepeatConstant {
            sleep: Duration::from_secs(1),
            max_attempts: 3,
        })
        .build();

    task.run(&mut runtime.grpc_client, token)
        .await
        .change_context(Error::HandlerTask)?;

    Ok(())
}

fn build_handler(
    runtime: &HandlerRuntime,
    chain_name: ChainName,
    handler_config: EvmHandlerConfig,
) -> Result<Handler<json_rpc::Client<Http>>, Error> {
    let rpc_client = json_rpc::Client::new_http(
        handler_config.rpc_url,
        reqwest::ClientBuilder::new()
            .connect_timeout(DEFAULT_RPC_TIMEOUT) // TODO: make this configurable
            .timeout(DEFAULT_RPC_TIMEOUT)
            .build()
            .change_context(Error::HandlerStart)?,
        runtime.monitoring_client.clone(),
        chain_name.clone(),
    );

    let handler = Handler::builder()
        .verifier(runtime.verifier.clone())
        .voting_verifier_contract(runtime.contracts.voting_verifier.clone())
        .chain(chain_name)
        .finalizer_type(Finalization::RPCFinalizedBlock) // TODO: make this configurable
        .rpc_client(rpc_client)
        .monitoring_client(runtime.monitoring_client.clone())
        .build();

    Ok(handler)
}
