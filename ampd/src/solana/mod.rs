use axelar_solana_gateway::processor::GatewayEvent;
use axelar_wasm_std::voting::Vote;
use gateway_event_stack::MatchContext;
use solana_sdk::pubkey::Pubkey;
use solana_transaction_status::{
    option_serializer::OptionSerializer, EncodedConfirmedTransactionWithStatusMeta,
};
use solana_transaction_status::{UiTransactionEncoding, UiTransactionStatusMeta};
use std::str::FromStr;
use std::str::FromStr;
use std::sync::Arc;
use tracing::error;

use futures::FutureExt;
use serde::{Deserialize, Deserializer};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{pubkey::Pubkey, signature::Signature};
use solana_transaction_status::UiTransactionStatusMeta;

pub mod msg_verifier;
pub mod verifier_set_verifier;

pub async fn fetch_message(
    rpc_client: &RpcClient,
    signature: Signature,
) -> Option<(Signature, UiTransactionStatusMeta)> {
    rpc_client
        .get_transaction(
            &signature,
            solana_transaction_status::UiTransactionEncoding::Base58,
        )
        .map(|tx_data_result| {
            tx_data_result
                .map(|tx_data| tx_data.transaction.meta)
                .ok()
                .flatten()
                .map(|tx_data| (signature, tx_data))
        })
        .await
}

pub fn deserialize_pubkey<'de, D>(deserializer: D) -> Result<Pubkey, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Pubkey::from_str(&s).map_err(serde::de::Error::custom)
}

pub fn verify<F>(
    source_gateway_address: &Pubkey,
    tx: &UiTransactionStatusMeta,
    desired_event_index: impl TryInto<usize>,
    evens_are_equal: F,
) -> Vote
where
    F: Fn(GatewayEvent) -> bool,
{
    let tx_was_successful = tx.err.is_none();
    let desired_event_idx: usize = match desired_event_index.try_into() {
        Ok(idx) => idx,
        Err(_) => {
            error!("Invalid event index in message ID");
            return Vote::NotFound;
        }
    };

    let context = MatchContext::new(&source_gateway_address.to_string());

    let logs = match tx.log_messages.as_ref() {
        OptionSerializer::Some(logs) => logs,
        _ => {
            error!("Logs not attached to the transaction object");
            return Vote::NotFound;
        }
    };

    let event_stack = gateway_event_stack::build_program_event_stack(
        &context,
        logs,
        gateway_event_stack::parse_gateway_logs,
    );

    use gateway_event_stack::ProgramInvocationState::*;

    for invocation_state in event_stack {
        let (vote, gateway_events) = match invocation_state {
            Succeeded(events) => (
                {
                    // if tx was successful and ix invocation was successful,
                    // then the final outcome (if event can be found) will be of `Vote::SucceededOnChain`
                    if tx_was_successful {
                        Vote::SucceededOnChain
                    } else {
                        // if tx was NOT successful then we don't care if the ix invocatoin succeeded,
                        // therefore the final outcome (if event can be found) will be of `Vote::FailedOnChain`
                        Vote::FailedOnChain
                    }
                },
                events,
            ),
            Failed(events) | InProgress(events) => (Vote::FailedOnChain, events),
        };

        if let Some((_, event)) = gateway_events
            .into_iter()
            .find(|(idx, _)| *idx == desired_event_idx)
        {
            if evens_are_equal(event) {
                // proxy the desired vote status of whether the ix succeeded
                return vote;
            }
            return Vote::NotFound;
        }
    }

    Vote::NotFound
}
