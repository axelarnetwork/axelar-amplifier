use axelar_wasm_std::nonempty;
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Coin;
use error_stack::{report, Result};
use report::ResultCompatExt;
use service_registry_api::msg::ExecuteMsg;
use valuable::Valuable;

use crate::commands::{broadcast_tx, verifier_pub_key, BroadcastArgs};
use crate::config::Config;
use crate::{Error, PREFIX};

#[derive(clap::Args, Debug, Valuable)]
pub struct Args {
    service_name: nonempty::String,
    /// Amount to bond. If omitted (along with `denom`), the transaction carries no funds, which
    /// the service registry interprets as a request to rebond stake currently in the
    /// `Unbonding` or `RequestedUnbonding` state.
    amount: Option<u128>,
    /// Denomination of the amount being bonded. Required if `amount` is provided.
    denom: Option<String>,
    #[clap(flatten)]
    broadcast: BroadcastArgs,
}

pub async fn run(config: Config, args: Args) -> Result<Option<String>, Error> {
    let Args {
        denom,
        amount,
        service_name,
        broadcast,
    } = args;

    let funds = build_funds(amount, denom)?;

    let pub_key = verifier_pub_key(config.tofnd_config.clone()).await?;

    let msg = serde_json::to_vec(&ExecuteMsg::BondVerifier {
        service_name: service_name.into(),
    })
    .expect("bond verifier msg should serialize");

    let tx = MsgExecuteContract {
        sender: pub_key.account_id(PREFIX).change_context(Error::Tofnd)?,
        contract: config.service_registry.cosmwasm_contract.as_ref().clone(),
        msg,
        funds,
    }
    .into_any()
    .expect("failed to serialize proto message");

    let tx_hash = broadcast_tx(config, tx, pub_key, broadcast.skip_confirmation).await?;

    Ok(Some(format!(
        "successfully broadcast bond verifier transaction, tx hash: {}",
        tx_hash
    )))
}

fn build_funds(amount: Option<u128>, denom: Option<String>) -> Result<Vec<Coin>, Error> {
    match (amount, denom) {
        (None, None) => Ok(vec![]),
        (Some(amount), Some(denom)) => Ok(vec![
            Coin::new(amount, denom.as_str()).change_context(Error::InvalidInput)?
        ]),
        _ => Err(report!(Error::InvalidInput)
            .attach_printable("amount and denom must be provided together")),
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: Args,
    }

    fn parse(input: &[&str]) -> std::result::Result<Args, clap::Error> {
        TestCli::try_parse_from(std::iter::once("test").chain(input.iter().copied()))
            .map(|cli| cli.args)
    }

    #[test]
    fn cli_accepts_service_name_only_for_rebond() {
        let args = parse(&["validators"]).unwrap();
        assert_eq!(args.amount, None);
        assert_eq!(args.denom, None);
    }

    #[test]
    fn cli_accepts_service_name_amount_and_denom() {
        let args = parse(&["validators", "100", "uaxl"]).unwrap();
        assert_eq!(args.amount, Some(100));
        assert_eq!(args.denom.as_deref(), Some("uaxl"));
    }

    #[test]
    fn build_funds_empty_when_neither_provided() {
        let funds = build_funds(None, None).unwrap();
        assert!(funds.is_empty());
    }

    #[test]
    fn build_funds_single_coin_when_both_provided() {
        let funds = build_funds(Some(100), Some("uaxl".into())).unwrap();
        assert_eq!(funds.len(), 1);
        assert_eq!(funds[0].amount, 100);
        assert_eq!(funds[0].denom.as_ref(), "uaxl");
    }

    #[test]
    fn build_funds_errors_when_only_amount_provided() {
        let err = build_funds(Some(100), None).unwrap_err();
        assert!(matches!(err.current_context(), Error::InvalidInput));
    }

    #[test]
    fn build_funds_errors_when_only_denom_provided() {
        let err = build_funds(None, Some("uaxl".into())).unwrap_err();
        assert!(matches!(err.current_context(), Error::InvalidInput));
    }
}
