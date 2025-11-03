use std::collections::HashMap;

use ampd::evm::finalizer::{self, Finalization};
use ampd::evm::json_rpc::EthereumClient;
use ampd::types::Hash;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::AccountId;
use error_stack::ResultExt;
use ethers_core::types::{TransactionReceipt, U64};
use events::AbciEventTypeFilter;
use futures::future::join_all;
use voting_verifier::msg::ExecuteMsg;

use crate::Error;

pub type Result<T> = error_stack::Result<T, Error>;

/// Retrieves finalized transaction receipts for one or more transactions
///
/// Returns a HashMap where keys are transaction hashes and values are receipts.
/// Only receipts that are finalized (at or before the latest finalized block) are included.
pub async fn finalized_tx_receipts<C, T>(
    rpc_client: &C,
    finalizer_type: &Finalization,
    tx_hashes: T,
    confirmation_height: u64,
) -> Result<HashMap<Hash, TransactionReceipt>>
where
    C: EthereumClient + Send + Sync,
    T: IntoIterator<Item = Hash>,
{
    let latest_finalized_block_height =
        finalizer::pick(finalizer_type, rpc_client, confirmation_height)
            .latest_finalized_block_height()
            .await
            .change_context(Error::Finalizer)?;

    Ok(join_all(
        tx_hashes
            .into_iter()
            .map(|tx_hash| rpc_client.transaction_receipt(tx_hash)),
    )
    .await
    .into_iter()
    .filter_map(std::result::Result::unwrap_or_default)
    .filter_map(|tx_receipt| {
        if tx_receipt
            .block_number
            .unwrap_or(U64::MAX)
            .le(&latest_finalized_block_height)
        {
            Some((tx_receipt.transaction_hash, tx_receipt))
        } else {
            None
        }
    })
    .collect())
}

/// Creates a vote message for one or more votes
///
/// Pass a single vote as `vec![vote]` or multiple votes as a vector.
pub fn vote_msg<V>(
    verifier: &AccountId,
    voting_verifier_contract: &AccountId,
    poll_id: PollId,
    votes: V,
) -> MsgExecuteContract
where
    V: Into<Vec<Vote>>,
{
    MsgExecuteContract {
        sender: verifier.clone(),
        contract: voting_verifier_contract.clone(),
        msg: serde_json::to_vec(&ExecuteMsg::Vote {
            poll_id,
            votes: votes.into(),
        })
        .expect("vote msg should serialize"),
        funds: vec![],
    }
}

/// Creates subscription parameters for event filtering
pub fn subscription_params(
    voting_verifier_contract: &AccountId,
    event_type: axelar_wasm_std::nonempty::String,
) -> ampd_sdk::event::event_handler::SubscriptionParams {
    ampd_sdk::event::event_handler::SubscriptionParams::new(
        vec![AbciEventTypeFilter {
            event_type,
            contract: voting_verifier_contract.clone(),
        }],
        false,
    )
}
