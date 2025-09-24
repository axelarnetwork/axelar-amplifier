use std::str::FromStr;

use event_cpi::Discriminator;

use axelar_solana_gateway::events::{CallContractEvent, GatewayEvent, VerifierSetRotatedEvent};
use axelar_solana_gateway::state::GatewayConfig;
use axelar_solana_gateway::BytemuckedPda;
use axelar_wasm_std::msg_id::Base58SolanaTxSignatureAndEventIndex;
use axelar_wasm_std::voting::Vote;
use borsh::BorshDeserialize;
use router_api::ChainName;
use serde::Deserializer;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_transaction_status::option_serializer::OptionSerializer;
use solana_sdk::transaction::TransactionError;
use solana_transaction_status::{UiCompiledInstruction, UiInnerInstructions, UiInstruction};
use tracing::{debug, error, warn};

use crate::monitoring;
use crate::monitoring::metrics::Msg;

pub mod msg_verifier;
pub mod verifier_set_verifier;

pub struct Client {
    client: RpcClient,
    monitoring_client: monitoring::Client,
    chain_name: ChainName,
}

impl Client {
    pub fn new(
        client: RpcClient,
        monitoring_client: monitoring::Client,
        chain_name: ChainName,
    ) -> Self {
        Self {
            client,
            monitoring_client,
            chain_name,
        }
    }
}

#[async_trait::async_trait]
pub trait SolanaRpcClientProxy: Send + Sync + 'static {
    async fn tx(&self, signature: &Signature) -> Option<SolanaTransaction>;
    async fn domain_separator(&self) -> Option<[u8; 32]>;
}

#[async_trait::async_trait]
impl SolanaRpcClientProxy for Client {
    async fn tx(&self, signature: &Signature) -> Option<SolanaTransaction> {
        let res = self
            .client
            .get_transaction(
                signature,
                solana_transaction_status::UiTransactionEncoding::Json,
            )
            .await;

        self.monitoring_client
            .metrics()
            .record_metric(Msg::RpcCall {
                chain_name: self.chain_name.clone(),
                success: res.is_ok(),
            });

        res.ok().and_then(|tx_data| {
            let meta = tx_data.transaction.meta?;
            let inner_instructions = match meta.inner_instructions.as_ref() {
                OptionSerializer::Some(inner) => inner.clone(),
                _ => vec![],
            };

            // Extract account keys and top-level instructions from the transaction
            let (account_keys, top_level_instructions) = match &tx_data.transaction.transaction {
                solana_transaction_status::EncodedTransaction::Json(ui_transaction) => {
                    match &ui_transaction.message {
                        solana_transaction_status::UiMessage::Raw(raw_message) => {
                            let account_keys = raw_message
                                .account_keys
                                .iter()
                                .filter_map(|key_str| Pubkey::from_str(key_str).ok())
                                .collect();
                            let top_level_instructions = raw_message.instructions.clone();
                            (account_keys, top_level_instructions)
                        }
                        _ => {
                            error!("RPC returned Parsed message, but we requested Raw message");
                            (vec![], vec![])
                        }
                    }
                }
                _ => {
                    error!("RPC returned non-JSON encoded transaction, but we requested JSON");
                    (vec![], vec![])
                }
            };

            Some(SolanaTransaction {
                signature: *signature,
                inner_instructions,
                top_level_instructions,
                err: meta.err.clone(),
                account_keys,
            })
        })
    }

    async fn domain_separator(&self) -> Option<[u8; 32]> {
        let (gateway_root_pda, ..) = axelar_solana_gateway::get_gateway_root_config_pda();

        let res = self.client.get_account(&gateway_root_pda).await;

        self.monitoring_client
            .metrics()
            .record_metric(Msg::RpcCall {
                chain_name: self.chain_name.clone(),
                success: res.is_ok(),
            });

        let config_data = res.ok()?.data;

        let config = *GatewayConfig::read(&config_data)?;
        let domain_separator = config.domain_separator;
        Some(domain_separator)
    }
}

pub fn deserialize_pubkey<'de, D>(deserializer: D) -> Result<Pubkey, D::Error>
where
    D: Deserializer<'de>,
{
    let s = <String as serde::Deserialize>::deserialize(deserializer)?;
    Pubkey::from_str(&s).map_err(serde::de::Error::custom)
}




#[derive(Clone, Debug)]
pub struct SolanaTransaction {
    pub signature: Signature,
    pub inner_instructions: Vec<UiInnerInstructions>,
    pub top_level_instructions: Vec<UiCompiledInstruction>,
    pub err: Option<TransactionError>,
    pub account_keys: Vec<Pubkey>,
}

pub fn verify<F>(
    tx: &SolanaTransaction,
    message_id: &Base58SolanaTxSignatureAndEventIndex,
    events_are_equal: F,
) -> Vote
where
    F: Fn(&GatewayEvent) -> bool,
{
    if tx.signature.as_ref() != message_id.raw_signature {
        error!("signatures don't match");
        return Vote::NotFound;
    }

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

    let instruction = match get_instruction_at_index(tx, desired_event_idx) {
        Some(inst) => inst,
        None => {
            error!("Instruction not found at index {}", desired_event_idx);
            return Vote::NotFound;
        }
    };

    if !is_instruction_from_gateway_program(&instruction, &tx.account_keys) {
        error!(
            "Instruction at index {} is not from gateway program",
            desired_event_idx
        );
        return Vote::NotFound;
    }

    let event = match parse_gateway_event_from_instruction(&instruction) {
        Ok(ev) => ev,
        Err(err) => {
            error!("Cannot parse gateway event from instruction: {}", err);
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

fn is_instruction_from_gateway_program(
    instruction: &UiCompiledInstruction,
    account_keys: &[Pubkey],
) -> bool {
    if account_keys.is_empty() {
        error!("No account keys found in transaction");
        return false;
    }

    let program_id_index = instruction.program_id_index as usize;
    if program_id_index >= account_keys.len() {
        debug!(
            "Invalid program_id_index: {} >= {}",
            program_id_index,
            account_keys.len()
        );
        return false;
    }

    let program_id = account_keys[program_id_index];
    if program_id != axelar_solana_gateway::ID {
        debug!(
            "Instruction not from gateway program. Expected: {}, got: {}",
            axelar_solana_gateway::ID, program_id
        );
        return false;
    }

    true
}

fn get_instruction_at_index(
    transaction: &SolanaTransaction,
    desired_event_idx: usize,
) -> Option<UiCompiledInstruction> {
    let mut index = 0;

    for group in transaction.inner_instructions.iter() {
        for instruction in group.instructions.iter() {
            if let UiInstruction::Compiled(ci) = instruction {
                if index == desired_event_idx {
                    return Some(ci.clone());
                }
                index = index.checked_add(1)?;
            }
        }
    }

    None
}


fn parse_gateway_event_from_instruction(
    instruction: &UiCompiledInstruction,
) -> Result<GatewayEvent, Box<dyn std::error::Error>> {
    let bytes = bs58::decode(&instruction.data)
        .into_vec()
        .map_err(|e| format!("Failed to decode instruction data: {:?}", e))?;

    if bytes.len() < 16 {
        return Err("Instruction data too short for CPI event".into());
    }

    if bytes.get(0..8) != Some(event_cpi::EVENT_IX_TAG_LE) {
        return Err(format!(
            "Expected CPI event discriminator, got {:?}",
            bytes.get(0..8)
        )
        .into());
    }

    let event_data = &bytes[16..];
    match bytes.get(8..16) {
        Some(disc) if disc == CallContractEvent::DISCRIMINATOR => {
            let call_contract_event = CallContractEvent::try_from_slice(event_data)
                .map_err(|e| format!("Failed to deserialize CallContract event: {:?}", e))?;
            Ok(GatewayEvent::CallContract(call_contract_event))
        }
        Some(disc) if disc == VerifierSetRotatedEvent::DISCRIMINATOR => {
            let verifier_set_rotated_event = VerifierSetRotatedEvent::try_from_slice(event_data)
                .map_err(|e| format!("Failed to deserialize VerifierSetRotated event: {:?}", e))?;
            Ok(GatewayEvent::VerifierSetRotated(verifier_set_rotated_event))
        }
        Some(disc) => Err(format!("Unknown event discriminator: {:?}", disc).into()),
        None => Err("Missing event discriminator".into()),
    }
}


#[cfg(test)]
mod test {
    use std::str::FromStr;

    use router_api::ChainName;
    use solana_client::nonblocking::rpc_client::RpcClient;
    use solana_sdk::signature::Signature;

    use super::{Client, SolanaRpcClientProxy};
    use crate::monitoring::metrics::Msg;
    use crate::monitoring::test_utils;


    #[tokio::test]
    async fn should_record_rpc_failure_metrics_successfully() {
        let (monitoring_client, mut receiver) = test_utils::monitoring_client();

        let client = Client::new(
            RpcClient::new("invalid_url".to_string()),
            monitoring_client,
            ChainName::from_str("solana").unwrap(),
        );

        let result = client.tx(&Signature::default()).await;
        assert!(result.is_none());

        let msg = receiver.recv().await.unwrap();
        assert_eq!(
            msg,
            Msg::RpcCall {
                chain_name: ChainName::from_str("solana").unwrap(),
                success: false,
            }
        );

        let result = client.domain_separator().await;
        assert!(result.is_none());

        let msg = receiver.recv().await.unwrap();
        assert_eq!(
            msg,
            Msg::RpcCall {
                chain_name: ChainName::from_str("solana").unwrap(),
                success: false,
            }
        );

        assert!(receiver.try_recv().is_err());
    }
}
