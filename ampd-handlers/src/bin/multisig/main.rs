mod error;
mod handler;

use ampd_handlers::tracing::init_tracing;
use ampd_sdk::config;
use ampd_sdk::runtime::HandlerRuntime;
use axelar_wasm_std::chain::ChainName;
#[cfg(debug_assertions)]
use dotenv_flow::dotenv_flow;
use error_stack::{Result, ResultExt};
use tokio_util::sync::CancellationToken;
use tracing::Level;

use crate::error::Error;
use crate::handler::Handler;

fn build_handler(runtime: &HandlerRuntime, chain_name: ChainName) -> Result<Handler, Error> {
    let handler = Handler::builder()
        .verifier(runtime.verifier.clone().into())
        .multisig(runtime.contracts.multisig.clone().into())
        .chain(chain_name)
        .build();

    Ok(handler)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    #[cfg(debug_assertions)]
    dotenv_flow().ok();

    init_tracing(Level::INFO);

    let base_config = config::Config::from_default_sources().change_context(Error::HandlerStart)?;

    let token = CancellationToken::new();

    let runtime = HandlerRuntime::start(&base_config, token.clone())
        .await
        .change_context(Error::HandlerStart)?;

    let handler = build_handler(&runtime, base_config.chain_name.clone())?;

    runtime
        .run_handler(handler, base_config, token)
        .await
        .change_context(Error::HandlerTask)?;

    Ok(())
}
