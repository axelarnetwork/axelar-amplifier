use std::path::Path;

use axelar_wasm_std::nonempty;
use connection_router::state::ChainName;
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use error_stack::Result;
use report::ResultCompatExt;
use service_registry::msg::ExecuteMsg;
use valuable::Valuable;

use crate::commands::{broadcast_tx, worker_pub_key};
use crate::config::Config;
use crate::{Error, PREFIX};

#[derive(clap::Args, Debug, Valuable)]
pub struct Args {
    pub service_name: nonempty::String,
    pub chains: Vec<ChainName>,
}

pub async fn run(config: Config, state_path: &Path, args: Args) -> Result<Option<String>, Error> {
    let pub_key = worker_pub_key(state_path, config.tofnd_config.clone()).await?;

    let msg = serde_json::to_vec(&ExecuteMsg::RegisterChainSupport {
        service_name: args.service_name.into(),
        chains: args.chains,
    })
    .expect("register chain support msg should serialize");

    let tx = MsgExecuteContract {
        sender: pub_key.account_id(PREFIX).change_context(Error::Tofnd)?,
        contract: config.service_registry.cosmwasm_contract.as_ref().clone(),
        msg,
        funds: vec![],
    }
    .into_any()
    .expect("failed to serialize proto message");

    let tx_hash = broadcast_tx(config, tx, pub_key).await?.txhash;

    Ok(Some(format!(
        "successfully broadcast register chain support transaction, tx hash: {}",
        tx_hash
    )))
}
