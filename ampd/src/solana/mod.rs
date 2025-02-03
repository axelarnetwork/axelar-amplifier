use axelar_solana_gateway::{processor::GatewayEvent, state::GatewayConfig, BytemuckedPda};
use axelar_wasm_std::msg_id::Base58SolanaTxSignatureAndEventIndex;
use axelar_wasm_std::voting::Vote;
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
            signature,
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
        let config = *GatewayConfig::read(&config_data)?;
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
    tx: (&Signature, &UiTransactionStatusMeta),
    message_id: &Base58SolanaTxSignatureAndEventIndex,
    events_are_equal: F,
) -> Vote
where
    F: Fn(&GatewayEvent) -> bool,
{
    // message id signatures must match
    let (signature, tx) = tx;
    if signature.as_ref() != message_id.raw_signature {
        error!("signatures don't match");
        return Vote::NotFound;
    }

    // the tx must be successful
    if tx.err.is_some() {
        error!("Transaction failed");
        return Vote::FailedOnChain;
    }

    // the event idx cannot be larger than usize
    let desired_event_idx: usize = match message_id.event_index.try_into() {
        Ok(idx) => idx,
        Err(_) => {
            error!("Invalid event index in message ID");
            return Vote::NotFound;
        }
    };

    // logs must be attached to the TX
    let logs = match tx.log_messages.as_ref() {
        OptionSerializer::Some(logs) => logs,
        _ => {
            error!("Logs not attached to the transaction object");
            return Vote::NotFound;
        }
    };

    // Check in the logs in a backward way the invocation comes from the gateway
    if !event_comes_from_gateway(logs, desired_event_idx) {
        error!("Event does not come from the gateway");
        return Vote::NotFound;
    }
    // Check that the event index is in the logs
    let Some(event_log) = logs.get(desired_event_idx) else {
        error!("Event index is out of bounds");
        return Vote::NotFound;
    };

    // Second ensure we can parse the event
    let event = match gateway_event_stack::parse_gateway_logs(event_log) {
        Ok(ev) => ev,
        Err(err) => {
            error!("Cannot parse the gateway log: {}", err);
            return Vote::NotFound;
        }
    };

    if events_are_equal(&event) {
        Vote::SucceededOnChain
    } else {
        warn!(?event, "event was found, but contents were not equal");
        Vote::NotFound
    }
}

// Check backward in the logs if the invocation comes from the gateway program,
// skipping native program invocations
fn event_comes_from_gateway(logs: &[String], desired_event_idx: usize) -> bool {
    let solana_gateway_id = axelar_solana_gateway::id().to_string();
    let system_program_id = solana_sdk::system_program::id().to_string();

    for log in logs.iter().take(desired_event_idx).rev() {
        let parts: Vec<&str> = log.split(' ').collect();

        if parts.len() < 3 && parts.len() > 4 {
            continue;
        }
        if parts[0] == "Program" && parts[2] == "invoke" {
            if parts[1] == system_program_id {
                continue;
            }
            if parts[1] == solana_gateway_id {
                return true;
            } else {
                break;
            }
        }
    }
    false
}
