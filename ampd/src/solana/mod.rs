use axelar_solana_gateway::{
    processor::GatewayEvent,
    state::{BytemuckedPda, GatewayConfig},
};
use axelar_wasm_std::msg_id::Base58SolanaTxSignatureAndEventIndex;
use axelar_wasm_std::voting::Vote;
use gateway_event_stack::MatchContext;
use solana_transaction_status::option_serializer::OptionSerializer;
use solana_transaction_status::UiTransactionStatusMeta;
use std::str::FromStr;
use tracing::{error, warn};

use futures::FutureExt;
use serde::{Deserialize, Deserializer};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{pubkey::Pubkey, signature::Signature};

pub mod msg_verifier;
pub mod verifier_set_verifier;

#[async_trait::async_trait]
pub trait SolanaRpcClientProxy: Send + Sync + 'static {
    async fn get_tx(&self, signature: &Signature) -> Option<UiTransactionStatusMeta>;
    async fn get_domain_separator(&self) -> Option<[u8; 32]>;
}

#[async_trait::async_trait]
impl SolanaRpcClientProxy for RpcClient {
    async fn get_tx(&self, signature: &Signature) -> Option<UiTransactionStatusMeta> {
        self.get_transaction(
            &signature,
            solana_transaction_status::UiTransactionEncoding::Base58,
        )
        .map(|tx_data_result| {
            tx_data_result
                .map(|tx_data| tx_data.transaction.meta)
                .ok()
                .flatten()
        })
        .await
    }

    async fn get_domain_separator(&self) -> Option<[u8; 32]> {
        let (gateway_root_pda, ..) = axelar_solana_gateway::get_gateway_root_config_pda();

        let config_data = self.get_account(&gateway_root_pda).await.ok()?.data;
        let config = *GatewayConfig::read(&config_data).ok()?;
        let domain_separator = config.domain_separator;
        Some(domain_separator)
    }
}

pub fn deserialize_pubkey<'de, D>(deserializer: D) -> Result<Pubkey, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Pubkey::from_str(&s).map_err(serde::de::Error::custom)
}

pub fn verify<F>(
    match_context: &MatchContext,
    tx: (&Signature, &UiTransactionStatusMeta),
    message_id: &Base58SolanaTxSignatureAndEventIndex,
    evens_are_equal: F,
) -> Vote
where
    F: Fn(&GatewayEvent) -> bool,
{
    // the event idx cannot be larger than usize
    let desired_event_idx: usize = match message_id.event_index.try_into() {
        Ok(idx) => idx,
        Err(_) => {
            error!("Invalid event index in message ID");
            return Vote::NotFound;
        }
    };

    // message id signatures must match
    let (signature, tx) = tx;
    if signature.as_ref() != message_id.raw_signature {
        error!("signatures don't match");
        return Vote::NotFound;
    }

    // logs must be attached to the TX
    let logs = match tx.log_messages.as_ref() {
        OptionSerializer::Some(logs) => logs,
        _ => {
            error!("Logs not attached to the transaction object");
            return Vote::NotFound;
        }
    };

    // pare the events
    let event_stack = gateway_event_stack::build_program_event_stack(
        &match_context,
        logs,
        gateway_event_stack::parse_gateway_logs,
    );

    for invocation_state in event_stack {
        use gateway_event_stack::ProgramInvocationState::*;
        let (vote, gateway_events) = match invocation_state {
            Succeeded(events) => (
                {
                    // if tx was successful and ix invocation was successful,
                    // then the final outcome (if event can be found) will be of `Vote::SucceededOnChain`
                    if tx.err.is_none() {
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
            if evens_are_equal(&event) {
                // proxy the desired vote status of whether the ix succeeded
                return vote;
            }

            warn!(?event, "event was found, but contents were not equal");
            return Vote::NotFound;
        }
    }

    warn!("not found");
    Vote::NotFound
}
