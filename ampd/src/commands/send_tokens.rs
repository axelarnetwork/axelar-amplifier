use axelar_wasm_std::nonempty;
use cosmrs::bank::MsgSend;
use cosmrs::tx::Msg;
use cosmrs::{AccountId, Coin};
use error_stack::Result;
use report::ResultCompatExt;
use valuable::Valuable;

use crate::commands::{broadcast_tx, verifier_pub_key};
use crate::config::Config;
use crate::{Error, PREFIX};

#[derive(clap::Args, Debug, Valuable)]
pub struct Args {
    pub to_address: nonempty::String,
    pub amount: u128,
    pub denom: nonempty::String,
}

pub async fn run(config: Config, args: Args) -> Result<Option<String>, Error> {
    let coin = Coin::new(args.amount, args.denom.as_str()).change_context(Error::InvalidInput)?;
    let pub_key = verifier_pub_key(config.tofnd_config.clone()).await?;

    let tx = MsgSend {
        to_address: args
            .to_address
            .parse::<AccountId>()
            .change_context(Error::InvalidInput)?,
        from_address: pub_key.account_id(PREFIX).change_context(Error::Tofnd)?,
        amount: vec![coin],
    }
    .into_any()
    .expect("failed to serialize proto message");

    let tx_hash = broadcast_tx(config, tx, pub_key).await?.txhash;

    Ok(Some(format!(
        "successfully broadcast send transaction, tx hash: {}",
        tx_hash
    )))
}
