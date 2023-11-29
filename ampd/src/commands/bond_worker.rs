use std::path::Path;

use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Coin;
use error_stack::Result;
use report::ResultCompatExt;
use service_registry::msg::ExecuteMsg;
use valuable::Valuable;

use crate::commands::{broadcast_tx, worker_pub_key};
use crate::config::Config;
use crate::{Error, PREFIX};

#[derive(clap::Args, Debug, Valuable)]
pub struct Args {
    pub amount: u128,
    pub denom: String,
}

pub async fn run(config: Config, state_path: &Path, args: Args) -> Result<(), Error> {
    let coin = Coin::new(args.amount, args.denom.as_str()).change_context(Error::Command)?;

    let pub_key = worker_pub_key(state_path, config.tofnd_config.clone()).await?;

    let msg = serde_json::to_vec(&ExecuteMsg::BondWorker {
        service_name: config.service_registry.service_name.clone(),
    })
    .expect("bond worker msg should serialize");

    let tx = MsgExecuteContract {
        sender: pub_key
            .account_id(PREFIX)
            .expect("failed to convert to account identifier"),
        contract: config.service_registry.cosmwasm_contract.as_ref().clone(),
        msg,
        funds: vec![coin],
    }
    .into_any()
    .expect("failed to serialize proto message");

    println!(
        "successfully broadcasted bond worker transaction, tx hash: {}",
        broadcast_tx(config, tx, pub_key).await?.txhash
    );

    Ok(())
}
