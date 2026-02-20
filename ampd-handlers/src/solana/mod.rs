use std::str::FromStr;

use ampd::monitoring;
use ampd::monitoring::metrics::Msg;
use anchor_lang::Discriminator;
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::msg_id::Base58SolanaTxSignatureAndEventIndex;
use axelar_wasm_std::nonempty;
use axelar_wasm_std::voting::Vote;
use borsh::BorshDeserialize;
use serde::Deserializer;
use solana_axelar_gateway::events::{CallContractEvent, VerifierSetRotatedEvent};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_client::rpc_config::{CommitmentConfig, RpcTransactionConfig};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_sdk::transaction::TransactionError;
use solana_transaction_status::option_serializer::OptionSerializer;
use solana_transaction_status::{
    EncodedConfirmedTransactionWithStatusMeta, UiCompiledInstruction, UiInnerInstructions,
    UiInstruction,
};
use tracing::{debug, error};

pub mod msg_verifier;
pub mod types;
pub mod verifier_set_verifier;

#[derive(Debug, Clone, PartialEq, Eq, BorshDeserialize)]
pub enum GatewayEvent {
    VerifierSetRotated(VerifierSetRotatedEvent),
    CallContract(CallContractEvent),
}

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
}

#[async_trait::async_trait]
impl SolanaRpcClientProxy for Client {
    async fn tx(&self, signature: &Signature) -> Option<SolanaTransaction> {
        let res = self
            .client
            .get_transaction_with_config(
                signature,
                RpcTransactionConfig {
                    encoding: Some(solana_transaction_status::UiTransactionEncoding::Json),
                    commitment: Some(CommitmentConfig::finalized()),
                    max_supported_transaction_version: Some(0),
                },
            )
            .await;

        self.monitoring_client
            .metrics()
            .record_metric(Msg::RpcCall {
                chain_name: self.chain_name.clone(),
                success: res.is_ok(),
            });

        res.ok()
            .and_then(|tx_data| parse_rpc_response(signature, tx_data))
    }
}

fn parse_rpc_response(
    signature: &Signature,
    tx_data: EncodedConfirmedTransactionWithStatusMeta,
) -> Option<SolanaTransaction> {
    let meta = tx_data.transaction.meta?;
    let inner_instructions = match meta.inner_instructions.as_ref() {
        OptionSerializer::Some(inner) => inner.clone(),
        _ => vec![],
    };

    // Extract account keys from the transaction
    let mut account_keys = match &tx_data.transaction.transaction {
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

    if let OptionSerializer::Some(loaded) = meta.loaded_addresses.as_ref() {
        account_keys.extend(
            loaded
                .writable
                .iter()
                .filter_map(|k| Pubkey::from_str(k).ok()),
        );
        account_keys.extend(
            loaded
                .readonly
                .iter()
                .filter_map(|k| Pubkey::from_str(k).ok()),
        );
    }

    Some(SolanaTransaction {
        signature: *signature,
        inner_instructions,
        err: meta.err.map(|e| e.into()),
        account_keys,
    })
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
    pub err: Option<TransactionError>,
    pub account_keys: Vec<Pubkey>,
}

pub fn verify<F>(
    tx: &SolanaTransaction,
    message_id: &Base58SolanaTxSignatureAndEventIndex,
    gateway_address: &Pubkey,
    events_are_equal: F,
) -> Vote
where
    F: Fn(&GatewayEvent) -> bool,
{
    if tx.signature.as_ref() != message_id.raw_signature {
        debug!("signatures don't match");
        return Vote::NotFound;
    }

    if tx.err.is_some() {
        debug!("Transaction failed");
        return Vote::FailedOnChain;
    }

    let instruction = match instruction_at_index(
        tx,
        message_id.inner_ix_group_index,
        message_id.inner_ix_index,
    ) {
        Some(inst) => inst,
        None => {
            debug!(
                "Solana tx instruction with tx signature {} not found at inner_ix_group_index: {}, inner_ix_index: {}",
                tx.signature,
                message_id.inner_ix_group_index.into_inner(),
                message_id.inner_ix_index.into_inner()
            );
            return Vote::NotFound;
        }
    };

    if !is_instruction_to_gateway_program(&instruction, &tx.account_keys, gateway_address) {
        debug!(
            "Solana tx instruction with tx signature {} at inner_ix_group_index: {}, inner_ix_index: {} is not from gateway program",
            tx.signature,
            message_id.inner_ix_group_index.into_inner(), message_id.inner_ix_index.into_inner()
        );
        return Vote::NotFound;
    }

    let event = match parse_gateway_event_from_instruction(&instruction) {
        Ok(ev) => ev,
        Err(err) => {
            debug!(
                "Cannot parse gateway event from Solana tx instruction with tx signature {}: {}",
                tx.signature, err
            );
            return Vote::NotFound;
        }
    };

    if events_are_equal(&event) {
        Vote::SucceededOnChain
    } else {
        debug!(
            ?event,
            "Solana tx with tx signature {} event was found, but contents were not equal",
            tx.signature,
        );
        Vote::NotFound
    }
}

fn is_instruction_to_gateway_program(
    instruction: &UiCompiledInstruction,
    account_keys: &[Pubkey],
    gateway_address: &Pubkey,
) -> bool {
    if account_keys.is_empty() {
        error!("No account keys found in Solana tx");
        return false;
    }

    let program_id_index = instruction.program_id_index as usize;
    if program_id_index >= account_keys.len() {
        debug!(
            "Invalid Solana tx program_id_index: {} >= {}",
            program_id_index,
            account_keys.len()
        );
        return false;
    }

    let program_id = account_keys[program_id_index];
    if program_id != *gateway_address {
        debug!(
            "Solana tx instruction not from gateway program. Expected: {}, got: {}",
            gateway_address, program_id
        );
        return false;
    }

    true
}

pub(crate) fn instruction_at_index(
    transaction: &SolanaTransaction,
    inner_ix_group_index: nonempty::Uint32,
    inner_ix_index: nonempty::Uint32,
) -> Option<UiCompiledInstruction> {
    let inner_ix_group_index = usize::try_from(inner_ix_group_index.into_inner()).ok()?;
    let inner_ix_index = usize::try_from(inner_ix_index.into_inner()).ok()?;

    let inner_group = transaction
        .inner_instructions
        .iter()
        .find(|group| usize::from(group.index) == inner_ix_group_index.saturating_sub(1))?;

    let inner_instruction_index = inner_ix_index.saturating_sub(1);
    let inner_instruction = inner_group.instructions.get(inner_instruction_index)?;

    if let UiInstruction::Compiled(ci) = inner_instruction {
        Some(ci.clone())
    } else {
        None
    }
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

    if bytes.get(0..8) != Some(anchor_lang::event::EVENT_IX_TAG_LE) {
        return Err(format!(
            "Expected CPI event discriminator, got {:?}",
            bytes.get(0..8)
        )
        .into());
    }

    let event_data = bytes.get(16..).ok_or("Missing event data")?;
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

    use ampd::monitoring::metrics::Msg;
    use ampd::monitoring::test_utils;
    use axelar_wasm_std::chain::ChainName;
    use solana_client::nonblocking::rpc_client::RpcClient;
    use solana_sdk::signature::Signature;
    use solana_transaction_status::option_serializer::OptionSerializer;
    use solana_transaction_status::{UiInnerInstructions, UiInstruction};

    use super::{Client, SolanaRpcClientProxy};

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

        assert!(receiver.try_recv().is_err());
    }

    /// Helper function to create an inner instruction
    fn create_inner_instruction(
        group_index: u32,
        inner_index: u32,
        program_id_index: u8,
    ) -> solana_transaction_status::UiCompiledInstruction {
        use solana_transaction_status::UiCompiledInstruction;
        UiCompiledInstruction {
            program_id_index,
            accounts: vec![0, 1],
            data: format!("inner_instruction_{}_{}", group_index, inner_index),
            stack_height: Some(2),
        }
    }

    /// Helper function to create an inner instruction group with specified number of instructions
    fn create_inner_instruction_group(
        group_index: u32,
        num_inner_instructions: u32,
    ) -> solana_transaction_status::UiInnerInstructions {
        let instructions = (0..num_inner_instructions)
            .map(|i| UiInstruction::Compiled(create_inner_instruction(group_index, i, 1)))
            .collect();

        UiInnerInstructions {
            index: u8::try_from(group_index).expect("group_index should fit in u8 for test"),
            instructions,
        }
    }

    /// Helper function to create a transaction with specified number of top-level instructions and inner instruction groups
    fn create_test_transaction(
        num_top_level: u32,
        inner_group_size: u32,
    ) -> crate::solana::SolanaTransaction {
        // Create inner instruction groups for all top-level instructions
        let inner_instructions = (0..num_top_level)
            .map(|i| create_inner_instruction_group(i, inner_group_size))
            .collect();

        crate::solana::SolanaTransaction {
            signature: [42; 64].into(),
            inner_instructions,
            err: None,
            account_keys: vec![],
        }
    }

    fn make_rpc_response(
        account_keys: Vec<String>,
        loaded_addresses: OptionSerializer<solana_transaction_status::UiLoadedAddresses>,
    ) -> solana_transaction_status::EncodedConfirmedTransactionWithStatusMeta {
        use solana_sdk::message::MessageHeader;
        use solana_transaction_status::{
            EncodedTransaction, EncodedTransactionWithStatusMeta, UiMessage, UiRawMessage,
            UiTransaction, UiTransactionStatusMeta,
        };

        let meta = UiTransactionStatusMeta {
            err: None,
            status: Ok(()),
            fee: 0,
            pre_balances: vec![],
            post_balances: vec![],
            inner_instructions: OptionSerializer::Some(vec![]),
            log_messages: OptionSerializer::None,
            pre_token_balances: OptionSerializer::None,
            post_token_balances: OptionSerializer::None,
            rewards: OptionSerializer::None,
            loaded_addresses,
            return_data: OptionSerializer::None,
            compute_units_consumed: OptionSerializer::None,
            cost_units: OptionSerializer::None,
        };

        solana_transaction_status::EncodedConfirmedTransactionWithStatusMeta {
            slot: 0,
            transaction: EncodedTransactionWithStatusMeta {
                transaction: EncodedTransaction::Json(UiTransaction {
                    signatures: vec![],
                    message: UiMessage::Raw(UiRawMessage {
                        header: MessageHeader {
                            num_required_signatures: 1,
                            num_readonly_signed_accounts: 0,
                            num_readonly_unsigned_accounts: 0,
                        },
                        account_keys,
                        recent_blockhash: String::new(),
                        instructions: vec![],
                        address_table_lookups: None,
                    }),
                }),
                meta: Some(meta),
                version: None,
            },
            block_time: None,
        }
    }

    #[test]
    fn parse_rpc_response_with_loaded_addresses() {
        use solana_sdk::pubkey::Pubkey;
        use solana_transaction_status::UiLoadedAddresses;

        let static_key = Pubkey::new_unique();
        let writable_key = Pubkey::new_unique();
        let readonly_key = Pubkey::new_unique();

        let resp = make_rpc_response(
            vec![static_key.to_string()],
            OptionSerializer::Some(UiLoadedAddresses {
                writable: vec![writable_key.to_string()],
                readonly: vec![readonly_key.to_string()],
            }),
        );

        let sig = Signature::default();
        let result = super::parse_rpc_response(&sig, resp).unwrap();

        assert_eq!(
            result.account_keys,
            vec![static_key, writable_key, readonly_key]
        );
    }

    #[test]
    fn parse_rpc_response_without_loaded_addresses() {
        use solana_sdk::pubkey::Pubkey;

        let static_key = Pubkey::new_unique();

        let resp = make_rpc_response(vec![static_key.to_string()], OptionSerializer::None);

        let sig = Signature::default();
        let result = super::parse_rpc_response(&sig, resp).unwrap();

        assert_eq!(result.account_keys, vec![static_key]);
    }

    #[test]
    fn parse_rpc_response_filters_invalid_loaded_address_pubkeys() {
        use solana_sdk::pubkey::Pubkey;
        use solana_transaction_status::UiLoadedAddresses;

        let static_key = Pubkey::new_unique();
        let valid_key = Pubkey::new_unique();

        let resp = make_rpc_response(
            vec![static_key.to_string()],
            OptionSerializer::Some(UiLoadedAddresses {
                writable: vec!["not_a_valid_pubkey".to_string(), valid_key.to_string()],
                readonly: vec!["also_invalid".to_string()],
            }),
        );

        let sig = Signature::default();
        let result = super::parse_rpc_response(&sig, resp).unwrap();

        assert_eq!(result.account_keys, vec![static_key, valid_key]);
    }

    #[test]
    fn parse_rpc_response_returns_none_when_no_meta() {
        use solana_transaction_status::{EncodedTransaction, EncodedTransactionWithStatusMeta};

        let resp = solana_transaction_status::EncodedConfirmedTransactionWithStatusMeta {
            slot: 0,
            transaction: EncodedTransactionWithStatusMeta {
                transaction: EncodedTransaction::LegacyBinary(String::new()),
                meta: None,
                version: None,
            },
            block_time: None,
        };

        let sig = Signature::default();
        assert!(super::parse_rpc_response(&sig, resp).is_none());
    }

    #[test]
    fn get_instruction_at_index_should_get_correct_instruction() {
        use super::instruction_at_index;

        const IX_GROUP_COUNT: u32 = 5;
        const INNER_GROUP_SIZE: u32 = 3;

        let tx = create_test_transaction(IX_GROUP_COUNT, INNER_GROUP_SIZE);

        let mut test_results: Vec<(u32, u32, String)> = Vec::new();

        for group_idx in 1..=IX_GROUP_COUNT {
            for inner_idx in 1..=INNER_GROUP_SIZE {
                let result = instruction_at_index(
                    &tx,
                    group_idx.try_into().unwrap(),
                    inner_idx.try_into().unwrap(),
                );
                let instruction = result.unwrap_or_else(|| {
                    panic!(
                        "Should find inner instruction {} for group {}",
                        inner_idx, group_idx
                    )
                });
                assert_eq!(
                    instruction.data,
                    format!("inner_instruction_{}_{}", group_idx - 1, inner_idx - 1)
                );

                // Collect for golden test
                test_results.push((group_idx, inner_idx, instruction.data));
            }
        }

        // Golden test
        goldie::assert_json!(test_results);
    }
}
