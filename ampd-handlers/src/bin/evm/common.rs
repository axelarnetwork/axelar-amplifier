use std::collections::HashMap;

use ampd::evm::finalizer::{self, Finalization};
use ampd::evm::json_rpc::EthereumClient;
use ampd::types::Hash;
use ampd_sdk::grpc::client::EventHandlerClient;
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::AccountId;
use error_stack::ResultExt;
use ethers_core::types::{TransactionReceipt, U64};
use futures::future::join_all;
use tracing::info;
use voting_verifier::msg::ExecuteMsg;

use crate::handler::Handler;
use crate::Error;

pub type Result<T> = error_stack::Result<T, Error>;

pub async fn should_skip_handling<HC, C>(
    handler: &Handler<C>,
    client: &mut HC,
    source_chain: ChainName,
    participants: Vec<AccountId>,
    expires_at: u64,
    poll_id: PollId,
) -> Result<bool>
where
    HC: EventHandlerClient + Send + 'static,
    C: EthereumClient + Send + Sync,
{
    // Skip if the source chain is not the same as the handler chain
    if source_chain != handler.chain {
        return Ok(true);
    }

    // Skip if the verifier is not a participant
    if !participants.contains(&handler.verifier) {
        return Ok(true);
    }

    // Skip if the poll has expired
    let latest_block_height = client
        .latest_block_height()
        .await
        .change_context(Error::EventHandling)?;
    if latest_block_height >= expires_at {
        info!(poll_id = poll_id.to_string(), "skipping expired poll");
        return Ok(true);
    }

    Ok(false)
}

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
