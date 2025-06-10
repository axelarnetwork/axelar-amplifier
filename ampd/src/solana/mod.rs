use std::str::FromStr;

use axelar_solana_gateway::processor::GatewayEvent;
use axelar_solana_gateway::state::GatewayConfig;
use axelar_solana_gateway::BytemuckedPda;
use axelar_wasm_std::msg_id::Base58SolanaTxSignatureAndEventIndex;
use axelar_wasm_std::voting::Vote;
use futures::FutureExt;
use serde::{Deserialize, Deserializer};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_transaction_status::option_serializer::OptionSerializer;
use solana_transaction_status::UiTransactionStatusMeta;
use tracing::{error, warn};

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

// XXX TODO: fix - error[E0117]: only traits defined in the current crate can be implemented for 
// types defined outside of the crate
// use std::fmt;
// impl fmt::Debug for RpcClient {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         // XXX: unable to access private struct fields
//         // (`sender` and `config`) but a debug impl is 
//         // required for adding SpanTrace error tracing
//         f.debug_struct("RpcClient")
//             // .field("sender", &self.sender)
//             // .field("config", &self.config)
//             .finish()
//     }
// }

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

    // the event idx cannot be larger than usize. However, a valid event will never have an index larger than usize,
    // as the native arch will be 64 bit, and the event index is a u64.
    let desired_event_idx: usize = match message_id.event_index.try_into() {
        Ok(idx) => idx,
        Err(_) => {
            error!("Cannot fit event index into system usize. Index was: {}, but current system usize is: {}", message_id.event_index, usize::MAX);
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
    let log = match event_comes_from_gateway(logs, desired_event_idx) {
        Ok(log) => log,
        Err(err) => {
            error!("Cannot find the gateway log: {}", err);
            return Vote::NotFound;
        }
    };

    // Second ensure we can parse the event
    let event = match gateway_event_stack::parse_gateway_logs(&log) {
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
// skipping native program invocations and returning the data log if the event comes from the gateway.
//
// Example logs input (indexes are just for reference):
//
// 1. Program gtwLjHAsfKAR6GWB4hzTUAA1w4SDdFMKamtGA5ttMEe invoke [1]
// 2. Program log: Instruction: Call Contract",
// 3. Program data: Y2FsbCBjb250cmFjdF9fXw== 6NGe5cm7PkXHz/g8V2VdRg0nU0l7R48x8lll4s0Clz0= xtlu5J3pLn7c4BhqnNSrP1wDZK/pQOJVCYbk6sroJhY= ZXRoZXJldW0= MHgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA2YzIwNjAzYzdiODc2NjgyYzEyMTczYmRlZjlhMWRjYTUyOGYxNGZk 8J+QqvCfkKrwn5Cq8J+Qqg==",
// 4. Program gtwLjHAsfKAR6GWB4hzTUAA1w4SDdFMKamtGA5ttMEe success"
//
// In the above log example, this function would return the data log at 3, if and only if the event comes from the gateway,
// which is determined by scanning log lines backwards till we find the pattern "Program <gateway_id> invoke" at 1 for the first time.
// It will fail if it finds any other invocation before the gateway invocation, except for the system program. In that case it will omit it and
// continue scanning.
fn event_comes_from_gateway(
    logs: &[String],
    desired_event_idx: usize,
) -> Result<&str, Box<dyn std::error::Error>> {
    let solana_gateway_id = axelar_solana_gateway::id().to_string();
    let system_program_id = solana_sdk::system_program::id().to_string();

    // From the logs, we take only the logs from the desired event index to the first log
    let mut logs = logs
        .iter()
        .take(
            desired_event_idx
                .checked_add(1)
                .expect("To add 1 to index count to get elem take"),
        )
        .rev(); // +1 because take() gets n elements, not index based.

    // This is the log that, if the event comes from the gateway, will contain the target data log
    // It will be returned if the event comes from the gateway.
    let data_log = logs.next().ok_or("Cannot find the first log")?;

    for log in logs {
        let mut parts = log.split(' ');

        let program = parts.next().ok_or("Cannot find program log part")?;
        let program_id = parts.next().ok_or("Cannot find program_id log part")?;
        let action = parts.next().ok_or("Cannot find action log part")?;

        if program == "Program" && action == "invoke" {
            if program_id == system_program_id {
                continue;
            }
            if program_id == solana_gateway_id {
                // We return the data log to be processed by further functions if we confirm the log comes from the gateway
                return Ok(data_log);
            }

            break;
        }
    }
    Err("Log does not belong to the gateway program".into())
}
