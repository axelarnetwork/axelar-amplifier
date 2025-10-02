use std::str::FromStr;

use axelar_solana_gateway::events::{CallContractEvent, GatewayEvent, VerifierSetRotatedEvent};
use axelar_solana_gateway::state::GatewayConfig;
use axelar_solana_gateway::BytemuckedPda;
use axelar_wasm_std::msg_id::Base58SolanaTxSignatureAndEventIndex;
use axelar_wasm_std::nonempty;
use axelar_wasm_std::voting::Vote;
use borsh::BorshDeserialize;
use event_cpi::Discriminator;
use router_api::ChainName;
use serde::Deserializer;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_sdk::transaction::TransactionError;
use solana_transaction_status::option_serializer::OptionSerializer;
use solana_transaction_status::{UiCompiledInstruction, UiInnerInstructions, UiInstruction};
use tracing::{debug, error};

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
            println!("meta: {:?}", meta);
            let inner_instructions = match meta.inner_instructions.as_ref() {
                OptionSerializer::Some(inner) => inner.clone(),
                _ => vec![],
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
                inner_instructions,
                err: meta.err.clone(),
                account_keys,
            })
        })
    }

    async fn domain_separator(&self) -> Option<[u8; 32]> {
        // Use the helper function from axelar-amplifier-solana to derive the gateway root config PDA
        let (gateway_root_pda, _) = axelar_solana_gateway::get_gateway_root_config_pda();

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
        debug!("signatures don't match");
        return Vote::NotFound;
    }

    if tx.err.is_some() {
        debug!("Transaction failed");
        return Vote::FailedOnChain;
    }

    let instruction = match get_instruction_at_index(
        tx,
        message_id.inner_ix_group_index,
        message_id.inner_ix_index,
    ) {
        Some(inst) => inst,
        None => {
            debug!(
                "Instruction not found at inner_ix_group_index: {}, inner_ix_index: {}",
                message_id.inner_ix_group_index.into_inner(),
                message_id.inner_ix_index.into_inner()
            );
            return Vote::NotFound;
        }
    };

    if !is_instruction_from_gateway_program(&instruction, &tx.account_keys) {
        debug!(
            "Instruction at inner_ix_group_index: {}, inner_ix_index: {} is not from gateway program",
            message_id.inner_ix_group_index.into_inner(), message_id.inner_ix_index.into_inner()
        );
        return Vote::NotFound;
    }

    let event = match parse_gateway_event_from_instruction(&instruction) {
        Ok(ev) => ev,
        Err(err) => {
            debug!("Cannot parse gateway event from instruction: {}", err);
            return Vote::NotFound;
        }
    };

    if events_are_equal(&event) {
        Vote::SucceededOnChain
    } else {
        debug!(?event, "event was found, but contents were not equal");
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
            axelar_solana_gateway::ID,
            program_id
        );
        return false;
    }

    true
}

pub(crate) fn get_instruction_at_index(
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

    if bytes.get(0..8) != Some(event_cpi::EVENT_IX_TAG_LE) {
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
        use solana_transaction_status::{UiInnerInstructions, UiInstruction};
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

    #[test]
    fn get_instruction_at_index_should_get_correct_instruction() {
        use super::get_instruction_at_index;

        const IX_GROUP_COUNT: u32 = 5;
        const INNER_GROUP_SIZE: u32 = 3;

        let tx = create_test_transaction(IX_GROUP_COUNT, INNER_GROUP_SIZE);

        let mut test_results: Vec<(u32, u32, String)> = Vec::new();

        for group_idx in 1..=IX_GROUP_COUNT {
            for inner_idx in 1..=INNER_GROUP_SIZE {
                let result = get_instruction_at_index(
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
