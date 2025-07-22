use axelar_wasm_std::nonempty;
use cosmrs::bank::MsgSend;
use cosmrs::tx::Msg;
use cosmrs::{AccountId, Coin};
use error_stack::Result;
use report::ResultCompatExt;
use valuable::Valuable;

use crate::commands::{broadcast_tx, verifier_pub_key, BroadcastArgs};
use crate::config::Config;
use crate::{Error, PREFIX};

#[derive(clap::Args, Debug, Valuable)]
pub struct Args {
    to_address: nonempty::String,
    amount: u128,
    denom: nonempty::String,
    #[clap(flatten)]
    broadcast: BroadcastArgs,
}

pub async fn run(config: Config, args: Args) -> Result<Option<String>, Error> {
    let Args {
        to_address,
        amount,
        denom,
        broadcast,
    } = args;

    let coin = Coin::new(amount, denom.as_str()).change_context(Error::InvalidInput)?;
    let pub_key = verifier_pub_key(config.tofnd_config.clone()).await?;

    let tx = MsgSend {
        to_address: to_address
            .parse::<AccountId>()
            .change_context(Error::InvalidInput)?,
        from_address: pub_key.account_id(PREFIX).change_context(Error::Tofnd)?,
        amount: vec![coin],
    }
    .into_any()
    .expect("failed to serialize proto message");

    let tx_hash = broadcast_tx(config, tx, pub_key, broadcast.skip_confirmation).await?;

    Ok(Some(format!(
        "successfully broadcast send transaction, tx hash: {}",
        tx_hash
    )))
}
