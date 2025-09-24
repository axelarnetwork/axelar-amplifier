use std::str::FromStr;

use axelar_solana_gateway::events::GatewayEvent;
use axelar_wasm_std::voting::Vote;
use router_api::ChainName;
use tracing::error;

use super::verify;
use crate::handlers::solana_verify_msg::Message;
use crate::solana::SolanaTransaction;

pub fn verify_message(tx: &SolanaTransaction, message: &Message) -> Vote {
    verify(tx, &message.message_id, |gateway_event| {
        let (sender, payload_hash, destination_chain, destination_contract_address) =
            match gateway_event {
                // This event is emitted when a contract call is initiated to an external chain.
                GatewayEvent::CallContract(event) => (
                    &event.sender,
                    &event.payload_hash,
                    &event.destination_chain,
                    &event.destination_contract_address,
                ),
                _ => return false,
            };

        let destination_chain = match ChainName::from_str(destination_chain) {
            Ok(cn) => cn,
            Err(err) => {
                error!("Cannot parse destination chain from event: {}", err);
                return false;
            }
        };

        message.source_address == *sender
            && message.payload_hash.0 == *payload_hash
            && message.destination_chain == destination_chain
            && message.destination_address == *destination_contract_address
    })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use axelar_solana_gateway::events::CallContractEvent;
    use event_cpi::Discriminator;
    use router_api::chain_name;
    use solana_sdk::pubkey::Pubkey;
    use solana_transaction_status::option_serializer::OptionSerializer;
    use solana_transaction_status::UiInstruction;

    use super::*;
    #[test_log::test]
    fn should_verify_msg_if_correct() {
        let (tx, _event, msg) = fixture_success_call_contract_tx_data();
        dbg!(&tx);
        assert_eq!(Vote::SucceededOnChain, verify_message(&tx, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_event_idx_is_invalid() {
        let (tx, _event, mut msg) = fixture_success_call_contract_tx_data();
        msg.message_id.inner_ix_index = 100;
        assert_eq!(Vote::NotFound, verify_message(&tx, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_destination_chain_does_not_match() {
        let (tx, _event, mut msg) = fixture_success_call_contract_tx_data();
        msg.destination_chain = chain_name!("badchain");
        assert_eq!(Vote::NotFound, verify_message(&tx, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_source_address_does_not_match() {
        let (tx, _event, mut msg) = fixture_success_call_contract_tx_data();
        msg.source_address = Pubkey::from([13; 32]);
        assert_eq!(Vote::NotFound, verify_message(&tx, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_destination_address_does_not_match() {
        let (tx, _event, mut msg) = fixture_success_call_contract_tx_data();
        msg.destination_address = "bad_address".to_string();
        assert_eq!(Vote::NotFound, verify_message(&tx, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_payload_hash_does_not_match() {
        let (tx, _event, mut msg) = fixture_success_call_contract_tx_data();
        msg.payload_hash = [1; 32].into();
        assert_eq!(Vote::NotFound, verify_message(&tx, &msg));
    }

    #[test]
    fn should_not_verify_msg_gateway_does_not_match() {
        let (mut tx, _event, msg) = fixture_success_call_contract_tx_data();
        // Replace the gateway program with a different program ID
        tx.account_keys = vec![Pubkey::new_unique()];
        assert_eq!(Vote::NotFound, verify_message(&tx, &msg));
    }

    #[test]
    fn should_fail_tx_failed() {
        let (tx, _event, msg) = fixture_success_call_contract_tx_data();

        // Create a failed transaction by setting the err field
        let mut failed_tx = tx;
        failed_tx.err = Some(solana_sdk::transaction::TransactionError::InstructionError(
            0,
            solana_sdk::instruction::InstructionError::Custom(1),
        ));

        assert_eq!(Vote::FailedOnChain, verify_message(&failed_tx, &msg));
    }

    #[test]
    fn should_find_the_correct_index() {
        // Create a transaction with multiple instructions to test index finding
        let (_base64_data, event) = fixture_call_contract_log();

        // Create two different call contract events for testing
        let call_contract_event1 = CallContractEvent {
            sender: solana_sdk::pubkey::Pubkey::new_unique(),
            destination_chain: "polygon".to_owned(),
            destination_contract_address: "0x1111111111111111111111111111111111111111".to_owned(),
            payload: vec![1, 2, 3, 4],
            payload_hash: [1; 32],
        };

        let call_contract_event2 = CallContractEvent {
            sender: solana_sdk::pubkey::Pubkey::from_str(
                "GfpyaXoJrd9XHHRehAPCGETie3wpM8xDxscAUoC12Cxt",
            )
            .unwrap(),
            destination_chain: "ethereum".to_owned(),
            destination_contract_address:
                "0x0000000000000000000000006c20603c7b876682c12173bdef9a1dca528f14fd".to_owned(),
            payload: vec![
                240, 159, 144, 170, 240, 159, 144, 170, 240, 159, 144, 170, 240, 159, 144, 170,
            ],
            payload_hash: [
                198, 217, 110, 228, 157, 233, 46, 126, 220, 224, 24, 106, 156, 212, 171, 63, 92, 3,
                100, 175, 233, 64, 226, 85, 9, 134, 228, 234, 202, 232, 38, 22,
            ],
        };

        // Create instructions for both events
        let mut instruction_data1 = Vec::new();
        instruction_data1.extend_from_slice(event_cpi::EVENT_IX_TAG_LE);
        instruction_data1.extend_from_slice(CallContractEvent::DISCRIMINATOR);
        instruction_data1.extend_from_slice(&borsh::to_vec(&call_contract_event1).unwrap());

        let mut instruction_data2 = Vec::new();
        instruction_data2.extend_from_slice(event_cpi::EVENT_IX_TAG_LE);
        instruction_data2.extend_from_slice(CallContractEvent::DISCRIMINATOR);
        instruction_data2.extend_from_slice(&borsh::to_vec(&call_contract_event2).unwrap());

        let compiled_instruction1 = solana_transaction_status::UiCompiledInstruction {
            program_id_index: 0,
            accounts: vec![],
            data: bs58::encode(&instruction_data1).into_string(),
            stack_height: Some(2),
        };

        let compiled_instruction2 = solana_transaction_status::UiCompiledInstruction {
            program_id_index: 0,
            accounts: vec![],
            data: bs58::encode(&instruction_data2).into_string(),
            stack_height: Some(2),
        };

        let instruction1 = UiInstruction::Compiled(compiled_instruction1);
        let instruction2 = UiInstruction::Compiled(compiled_instruction2);

        let inner_instructions = vec![solana_transaction_status::UiInnerInstructions {
            index: 0,
            instructions: vec![instruction1, instruction2],
        }];

        let msg = create_msg_counterpart(&event, 0, 2); // Look for the second instruction in group 0 (inner_ix_index 2 = 1-based index)
        let signature = msg.message_id.raw_signature.into();

        let solana_tx = crate::solana::SolanaTransaction {
            signature,
            inner_instructions,
            top_level_instructions: vec![],
            err: None,
            account_keys: vec![axelar_solana_gateway::ID], // Gateway program at index 0
        };

        assert_eq!(Vote::SucceededOnChain, verify_message(&solana_tx, &msg));
    }

    const RAW_SIGNATURE: [u8; 64] = [42; 64];

    fn fixture_call_contract_log() -> (String, CallContractEvent) {
        // this is a `CallContract` extract form other unittests
        let base64_data = "Y2FsbCBjb250cmFjdF9fXw== 6NGe5cm7PkXHz/g8V2VdRg0nU0l7R48x8lll4s0Clz0= xtlu5J3pLn7c4BhqnNSrP1wDZK/pQOJVCYbk6sroJhY= ZXRoZXJldW0= MHgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA2YzIwNjAzYzdiODc2NjgyYzEyMTczYmRlZjlhMWRjYTUyOGYxNGZk 8J+QqvCfkKrwn5Cq8J+Qqg==";
        // Simple `CallContract` fixture
        let event = CallContractEvent {
            sender: Pubkey::from_str("GfpyaXoJrd9XHHRehAPCGETie3wpM8xDxscAUoC12Cxt").unwrap(),
            destination_chain: "ethereum".to_owned(),
            destination_contract_address:
                "0x0000000000000000000000006c20603c7b876682c12173bdef9a1dca528f14fd".to_owned(),
            payload: vec![
                240, 159, 144, 170, 240, 159, 144, 170, 240, 159, 144, 170, 240, 159, 144, 170,
            ],
            payload_hash: [
                198, 217, 110, 228, 157, 233, 46, 126, 220, 224, 24, 106, 156, 212, 171, 63, 92, 3,
                100, 175, 233, 64, 226, 85, 9, 134, 228, 234, 202, 232, 38, 22,
            ],
        };

        (base64_data.to_string(), event)
    }

    fn create_msg_counterpart(
        event: &CallContractEvent,
        top_level_ix_index: u32,
        inner_ix_index: u32,
    ) -> Message {
        Message {
            message_id: axelar_wasm_std::msg_id::Base58SolanaTxSignatureAndEventIndex {
                raw_signature: RAW_SIGNATURE,
                top_level_ix_index,
                inner_ix_index,
            },
            destination_address: event.destination_contract_address.clone(),
            destination_chain: event.destination_chain.clone().parse().unwrap(),
            source_address: event.sender,
            payload_hash: event.payload_hash.into(),
        }
    }

    fn fixture_success_call_contract_tx_data(
    ) -> (crate::solana::SolanaTransaction, CallContractEvent, Message) {
        let (base64_data, event) = fixture_call_contract_log();
        let logs = vec![
            format!("Program {} invoke [1]", axelar_solana_gateway::ID), // Invocation 1 starts
            "Program log: Instruction: Call Contract".to_owned(),
            format!("Program data: {}", base64_data),
            format!("Program {} success", axelar_solana_gateway::ID), // Invocation 1 succeeds
        ];

        let msg = create_msg_counterpart(&event, 0, 1); // Use inner_ix_index 1 (first inner instruction in group 0)
        let signature = msg.message_id.raw_signature.into();
        let tx_meta = tx_meta(logs);

        let solana_tx = crate::solana::SolanaTransaction {
            signature,
            inner_instructions: tx_meta.inner_instructions.as_ref().unwrap().clone(),
            top_level_instructions: vec![],
            err: None,
            account_keys: vec![axelar_solana_gateway::ID], // Gateway program at index 0
        };

        (solana_tx, event, msg)
    }

    fn tx_meta(logs: Vec<String>) -> solana_transaction_status::UiTransactionStatusMeta {
        // Create mock CPI instruction data for CallContract event
        let call_contract_event = CallContractEvent {
            sender: solana_sdk::pubkey::Pubkey::from_str(
                "GfpyaXoJrd9XHHRehAPCGETie3wpM8xDxscAUoC12Cxt",
            )
            .unwrap(),
            destination_chain: "ethereum".to_owned(),
            destination_contract_address:
                "0x0000000000000000000000006c20603c7b876682c12173bdef9a1dca528f14fd".to_owned(),
            payload: vec![
                240, 159, 144, 170, 240, 159, 144, 170, 240, 159, 144, 170, 240, 159, 144, 170,
            ],
            payload_hash: [
                198, 217, 110, 228, 157, 233, 46, 126, 220, 224, 24, 106, 156, 212, 171, 63, 92, 3,
                100, 175, 233, 64, 226, 85, 9, 134, 228, 234, 202, 232, 38, 22,
            ],
        };

        // Serialize the event with discriminators
        let mut instruction_data = Vec::new();
        instruction_data.extend_from_slice(event_cpi::EVENT_IX_TAG_LE);
        instruction_data.extend_from_slice(CallContractEvent::DISCRIMINATOR);
        instruction_data.extend_from_slice(&borsh::to_vec(&call_contract_event).unwrap());

        let compiled_instruction = solana_transaction_status::UiCompiledInstruction {
            program_id_index: 0,
            accounts: vec![],
            data: bs58::encode(&instruction_data).into_string(),
            stack_height: Some(2),
        };

        let instruction = UiInstruction::Compiled(compiled_instruction);

        let inner_instructions = vec![solana_transaction_status::UiInnerInstructions {
            index: 0,
            instructions: vec![instruction],
        }];

        solana_transaction_status::UiTransactionStatusMeta {
            err: None,
            status: Ok(()),
            fee: 0,
            pre_balances: vec![0],
            post_balances: vec![0],
            inner_instructions: OptionSerializer::Some(inner_instructions),
            log_messages: OptionSerializer::Some(logs),
            pre_token_balances: OptionSerializer::None,
            post_token_balances: OptionSerializer::None,
            rewards: OptionSerializer::None,
            loaded_addresses: OptionSerializer::None,
            return_data: OptionSerializer::None,
            compute_units_consumed: OptionSerializer::None,
        }
    }
}
