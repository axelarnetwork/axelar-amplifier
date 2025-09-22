use std::str::FromStr;

use axelar_solana_gateway::processor::GatewayEvent;
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
use solana_sdk::transaction::TransactionError;
use solana_transaction_status::option_serializer::OptionSerializer;
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
                _ => return None,
            };

            // Extract account keys from the transaction
            let account_keys = match &tx_data.transaction.transaction {
                solana_transaction_status::EncodedTransaction::Json(ui_transaction) => {
                    match &ui_transaction.message {
                        solana_transaction_status::UiMessage::Raw(raw_message) => raw_message
                            .account_keys
                            .iter()
                            .filter_map(|key_str| Pubkey::from_str(key_str).ok())
                            .collect(),
                            _ => {
                                error!("RPC returned Parsed message, but we requested Raw message");
                                vec![]
                            }
                    }
                }
                _ => {
                    error!("RPC returned non-JSON encoded transaction, but we requested JSON");
                    vec![]
                }
            };

            Some(SolanaTransaction {
                signature: *signature,
                ixs: inner_instructions,
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

// CPI event discriminators - these identify the event type in CPI instructions
const CPI_EVENT_DISC: [u8; 8] = [228, 69, 165, 46, 81, 203, 154, 29]; // EVENT_IX_TAG in LE
const CALL_CONTRACT_EVENT_DISC: [u8; 8] = [211, 211, 80, 126, 150, 98, 181, 198];
const VERIFIER_SET_ROTATED_EVENT_DISC: [u8; 8] = [66, 220, 124, 251, 31, 123, 214, 18];

// Gateway program ID for validation
pub const GATEWAY_PROGRAM_ID: Pubkey = axelar_solana_gateway::ID;

/// Internal struct for deserializing CallContract events from CPI instructions
#[derive(BorshDeserialize, borsh::BorshSerialize, Clone, Debug)]
pub struct CallContractEventData {
    /// Sender's public key.
    pub sender_key: Pubkey,
    /// Payload hash, 32 bytes.
    pub payload_hash: [u8; 32],
    /// Destination chain as a `String`.
    pub destination_chain: String,
    /// Destination contract address as a `String`.
    pub destination_contract_address: String,
    /// Payload data as a `Vec<u8>`.
    pub payload: Vec<u8>,
}

/// Internal struct for deserializing VerifierSetRotated events from CPI instructions
#[derive(BorshDeserialize, borsh::BorshSerialize, Clone, Debug)]
pub struct VerifierSetRotatedEventData {
    /// Epoch of the new verifier set (U256 as 32 bytes little-endian)
    pub epoch: [u8; 32],
    /// The hash of the new verifier set
    pub verifier_set_hash: [u8; 32],
}

/// Simplified SolanaTransaction structure for parsing
#[derive(Clone, Debug)]
pub struct SolanaTransaction {
    pub signature: Signature,
    pub ixs: Vec<UiInnerInstructions>,
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
    // message id signatures must match
    if tx.signature.as_ref() != message_id.raw_signature {
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
    if program_id != GATEWAY_PROGRAM_ID {
        debug!(
            "Instruction not from gateway program. Expected: {}, got: {}",
            GATEWAY_PROGRAM_ID, program_id
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

    for group in transaction.ixs.iter() {
        for inst in group.instructions.iter() {
            if let UiInstruction::Compiled(ci) = inst {
                if index == desired_event_idx {
                    return Some(ci.clone());
                }
                index = index.checked_add(1)?;
            }
        }
    }

    None
}

fn parse_call_contract_event_from_instruction(
    instruction: &UiCompiledInstruction,
) -> Result<GatewayEvent, Box<dyn std::error::Error>> {
    let bytes = bs58::decode(&instruction.data)
        .into_vec()
        .map_err(|e| format!("Failed to decode instruction data: {:?}", e))?;

    if bytes.len() < 16 {
        return Err("Instruction data too short for CPI event".into());
    }

    if bytes.get(0..8) != Some(CPI_EVENT_DISC.as_slice()) {
        return Err(format!(
            "Expected CPI event discriminator, got {:?}",
            bytes.get(0..8)
        )
        .into());
    }

    if bytes.get(8..16) != Some(CALL_CONTRACT_EVENT_DISC.as_slice()) {
        return Err(format!(
            "Expected CallContract event discriminator, got {:?}",
            bytes.get(8..16)
        )
        .into());
    }

    let event_data = &bytes[16..];
    let call_contract_event_data = CallContractEventData::try_from_slice(event_data)
        .map_err(|e| format!("Failed to deserialize CallContract event: {:?}", e))?;

    Ok(GatewayEvent::CallContract(
        axelar_solana_gateway::processor::CallContractEvent {
            sender_key: call_contract_event_data.sender_key,
            payload_hash: call_contract_event_data.payload_hash,
            destination_chain: call_contract_event_data.destination_chain,
            destination_contract_address: call_contract_event_data.destination_contract_address,
            payload: call_contract_event_data.payload,
        },
    ))
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

    if bytes.get(0..8) != Some(CPI_EVENT_DISC.as_slice()) {
        return Err(format!(
            "Expected CPI event discriminator, got {:?}",
            bytes.get(0..8)
        )
        .into());
    }

    match bytes.get(8..16) {
        Some(disc) if disc == CALL_CONTRACT_EVENT_DISC.as_slice() => {
            parse_call_contract_event_from_instruction(instruction)
        }
        Some(disc) if disc == VERIFIER_SET_ROTATED_EVENT_DISC.as_slice() => {
            parse_verifier_set_rotated_event_from_instruction(instruction)
        }
        Some(disc) => Err(format!("Unknown event discriminator: {:?}", disc).into()),
        None => Err("Missing event discriminator".into()),
    }
}

fn parse_verifier_set_rotated_event_from_instruction(
    instruction: &UiCompiledInstruction,
) -> Result<GatewayEvent, Box<dyn std::error::Error>> {
    let bytes = bs58::decode(&instruction.data)
        .into_vec()
        .map_err(|e| format!("Failed to decode instruction data: {:?}", e))?;

    if bytes.len() < 16 {
        return Err("Instruction data too short for CPI event".into());
    }

    if bytes.get(0..8) != Some(CPI_EVENT_DISC.as_slice()) {
        return Err(format!(
            "Expected CPI event discriminator, got {:?}",
            bytes.get(0..8)
        )
        .into());
    }

    if bytes.get(8..16) != Some(VERIFIER_SET_ROTATED_EVENT_DISC.as_slice()) {
        return Err(format!(
            "Expected VerifierSetRotated event discriminator, got {:?}",
            bytes.get(8..16)
        )
        .into());
    }

    let event_data = &bytes[16..];
    let verifier_set_rotated_data = VerifierSetRotatedEventData::try_from_slice(event_data)
        .map_err(|e| format!("Failed to deserialize VerifierSetRotated event: {:?}", e))?;

    let verifier_set_rotated = axelar_solana_gateway::processor::VerifierSetRotated::new(
        [verifier_set_rotated_data.epoch.to_vec(), verifier_set_rotated_data.verifier_set_hash.to_vec()].into_iter()
    ).map_err(|e| format!("Failed to construct VerifierSetRotated: {:?}", e))?;

    Ok(GatewayEvent::VerifierSetRotated(verifier_set_rotated))
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
