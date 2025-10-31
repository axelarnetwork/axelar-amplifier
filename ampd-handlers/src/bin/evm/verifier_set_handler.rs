use ampd::evm::json_rpc::EthereumClient;
use ampd::evm::verifier::verify_verifier_set;
use ampd::handlers::evm_verify_verifier_set::VerifierSetConfirmation;
use ampd::monitoring::metrics;
use ampd::types::EVMAddress;
use ampd_sdk::grpc::client::EventHandlerClient;
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::tx::Msg;
use cosmrs::{AccountId, Any};
use error_stack::ResultExt;
use events::try_from;
use serde::Deserialize;
use tracing::{info, info_span};
use valuable::Valuable;

use crate::handler::Handler;
use crate::{common, Error};

type Result<T> = common::Result<T>;

#[derive(Clone, Debug, Deserialize)]
#[try_from("wasm-verifier_set_poll_started")]
pub struct VerifierSetPollStarted {
    verifier_set: VerifierSetConfirmation,
    poll_id: PollId,
    source_chain: ChainName,
    source_gateway_address: EVMAddress,
    expires_at: u64,
    confirmation_height: u64,
    participants: Vec<AccountId>,
}

pub async fn handle_verifier_set<HC, C>(
    handler: &Handler<C>,
    event: VerifierSetPollStarted,
    client: &mut HC,
) -> Result<Vec<Any>>
where
    HC: EventHandlerClient + Send + 'static,
    C: EthereumClient + Send + Sync,
{
    let VerifierSetPollStarted {
        poll_id,
        source_chain,
        source_gateway_address,
        expires_at,
        confirmation_height,
        participants,
        verifier_set,
    } = event;

    if handler.chain != source_chain {
        return Ok(vec![]);
    }

    if !participants.contains(&handler.verifier) {
        return Ok(vec![]);
    }

    let latest_block_height = client
        .latest_block_height()
        .await
        .change_context(Error::EventHandling)?;
    if latest_block_height >= expires_at {
        info!(poll_id = poll_id.to_string(), "skipping expired poll");
        return Ok(vec![]);
    }

    let tx_hash: ampd::types::Hash = verifier_set.message_id.tx_hash.into();
    let finalized_tx_receipts = common::finalized_tx_receipts(
        &handler.rpc_client,
        &handler.finalizer_type,
        [tx_hash],
        confirmation_height,
    )
    .await?;
    let tx_receipt = finalized_tx_receipts.get(&tx_hash).cloned();

    let vote = info_span!(
        "verify a new verifier set for an EVM chain",
        poll_id = poll_id.to_string(),
        source_chain = source_chain.to_string(),
        id = verifier_set.message_id.to_string()
    )
    .in_scope(|| {
        info!("ready to verify a new verifier set in poll");

        let vote = tx_receipt.map_or(Vote::NotFound, |tx_receipt| {
            verify_verifier_set(&source_gateway_address, &tx_receipt, &verifier_set)
        });

        handler
            .monitoring_client
            .metrics()
            .record_metric(metrics::Msg::VerificationVote {
                vote_decision: vote.clone(),
                chain_name: handler.chain.clone(),
            });

        info!(
            vote = vote.as_value(),
            "ready to vote for a new verifier set in poll"
        );

        vote
    });

    Ok(vec![common::vote_msg(
        &handler.verifier,
        &handler.voting_verifier_contract,
        poll_id,
        vec![vote],
    )
    .into_any()
    .expect("vote msg should serialize")])
}
