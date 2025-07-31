use axelar_wasm_std::nonempty;
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use error_stack::Result;
use report::ResultCompatExt;
use router_api::ChainName;
use service_registry_api::msg::ExecuteMsg;
use valuable::Valuable;

use crate::commands::{broadcast_tx, verifier_pub_key, BroadcastArgs};
use crate::config::Config;
use crate::{Error, PREFIX};

#[derive(clap::Args, Debug, Valuable)]
pub struct Args {
    service_name: nonempty::String,
    chains: Vec<ChainName>,
    #[clap(flatten)]
    broadcast: BroadcastArgs,
}

pub async fn run(config: Config, args: Args) -> Result<Option<String>, Error> {
    let Args {
        service_name,
        chains,
        broadcast,
    } = args;

    let pub_key = verifier_pub_key(config.tofnd_config.clone()).await?;

    let msg = serde_json::to_vec(&ExecuteMsg::DeregisterChainSupport {
        service_name: service_name.into(),
        chains,
    })
    .expect("deregister chain support msg should serialize");

    let tx = MsgExecuteContract {
        sender: pub_key.account_id(PREFIX).change_context(Error::Tofnd)?,
        contract: config.service_registry.cosmwasm_contract.as_ref().clone(),
        msg,
        funds: vec![],
    }
    .into_any()
    .expect("failed to serialize proto message");

    let tx_hash = broadcast_tx(config, tx, pub_key, broadcast.skip_confirmation).await?;

    Ok(Some(format!(
        "successfully broadcast deregister chain support transaction, tx hash: {}",
        tx_hash
    )))
}
