use axelar_wasm_std::nonempty;
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Coin;
use error_stack::Result;
use report::ResultCompatExt;
use service_registry::msg::ExecuteMsg;
use valuable::Valuable;

use crate::commands::{broadcast_tx, verifier_pub_key};
use crate::config::Config;
use crate::{Error, PREFIX};

#[derive(clap::Args, Debug, Valuable)]
pub struct Args {
    pub service_name: nonempty::String,
    pub amount: u128,
    pub denom: String,
}

pub async fn run(config: Config, args: Args) -> Result<Option<String>, Error> {
    let coin = Coin::new(args.amount, args.denom.as_str()).change_context(Error::InvalidInput)?;

    let pub_key = verifier_pub_key(config.tofnd_config.clone()).await?;

    let msg = serde_json::to_vec(&ExecuteMsg::BondVerifier {
        service_name: args.service_name.into(),
    })
    .expect("bond verifier msg should serialize");

    let tx = MsgExecuteContract {
        sender: pub_key.account_id(PREFIX).change_context(Error::Tofnd)?,
        contract: config.service_registry.cosmwasm_contract.as_ref().clone(),
        msg,
        funds: vec![coin],
    }
    .into_any()
    .expect("failed to serialize proto message");

    let tx_hash = broadcast_tx(config, tx, pub_key).await?.txhash;

    Ok(Some(format!(
        "successfully broadcast bond verifier transaction, tx hash: {}",
        tx_hash
    )))
}
