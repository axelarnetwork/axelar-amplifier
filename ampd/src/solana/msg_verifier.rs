use axelar_solana_gateway::processor::GatewayEvent;
use axelar_wasm_std::voting::Vote;
use solana_sdk::signature::Signature;
use solana_transaction_status::UiTransactionStatusMeta;

use super::verify;
use crate::handlers::solana_verify_msg::Message;

pub fn verify_message(tx: (&Signature, &UiTransactionStatusMeta), message: &Message) -> Vote {
    verify(tx, &message.message_id, |gateway_event| {
        let (sender, payload_hash, destination_chain, destination_contract_address) =
            match gateway_event {
                // This event is emitted when a contract call is initiated to an external chain.
                GatewayEvent::CallContract(event) => (
                    &event.sender_key,
                    &event.payload_hash,
                    &event.destination_chain,
                    &event.destination_contract_address,
                ),
                // This event is emitted when a contract call is initiated to an external chain with call data
                // being passed offchain.
                GatewayEvent::CallContractOffchainData(event) => (
                    &event.sender_key,
                    &event.payload_hash,
                    &event.destination_chain,
                    &event.destination_contract_address,
                ),
                _ => return false,
            };

        message.source_address == *sender
            && message.payload_hash.0 == *payload_hash
            && message.destination_chain == *destination_chain
            && message.destination_address == *destination_contract_address
    })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use axelar_solana_gateway::processor::CallContractEvent;
    use router_api::ChainName;
    use solana_sdk::pubkey::Pubkey;
    use solana_transaction_status::option_serializer::OptionSerializer;

    use super::*;
    #[test_log::test]
    fn should_verify_msg_if_correct() {
        let ((signature, tx), _event, msg) = fixture_success_call_contract_tx_data();
        dbg!(&tx);
        assert_eq!(
            Vote::SucceededOnChain,
            verify_message((&signature, &tx), &msg)
        );
    }

    #[test]
    fn should_not_verify_msg_if_event_idx_is_invalid() {
        let ((signature, tx), _event, mut msg) = fixture_success_call_contract_tx_data();
        msg.message_id.event_index = 100;
        assert_eq!(Vote::NotFound, verify_message((&signature, &tx), &msg));
    }

    #[test]
    fn should_not_verify_msg_if_destination_chain_does_not_match() {
        let ((signature, tx), _event, mut msg) = fixture_success_call_contract_tx_data();
        msg.destination_chain = ChainName::from_str("badchain").unwrap();
        assert_eq!(Vote::NotFound, verify_message((&signature, &tx), &msg));
    }

    #[test]
    fn should_not_verify_msg_if_source_address_does_not_match() {
        let ((signature, tx), _event, mut msg) = fixture_success_call_contract_tx_data();
        msg.source_address = Pubkey::from([13; 32]);
        assert_eq!(Vote::NotFound, verify_message((&signature, &tx), &msg));
    }

    #[test]
    fn should_not_verify_msg_if_destination_address_does_not_match() {
        let ((signature, tx), _event, mut msg) = fixture_success_call_contract_tx_data();
        msg.destination_address = "bad_address".to_string();
        assert_eq!(Vote::NotFound, verify_message((&signature, &tx), &msg));
    }

    #[test]
    fn should_not_verify_msg_if_payload_hash_does_not_match() {
        let ((signature, tx), _event, mut msg) = fixture_success_call_contract_tx_data();
        msg.payload_hash = [1; 32].into();
        assert_eq!(Vote::NotFound, verify_message((&signature, &tx), &msg));
    }

    #[test]
    fn should_not_verify_msg_gateway_does_not_match() {
        let ((signature, tx), _event, msg) = fixture_bad_gateway_call_contract_tx_data();
        assert_eq!(Vote::NotFound, verify_message((&signature, &tx), &msg));
    }

    #[test]
    fn should_fail_tx_failed() {
        let (base64_data, event) = fixture_call_contract_log();
        let logs = vec![
            format!("Program {GATEWAY_PROGRAM_ID} invoke [1]"),
            "Program log: Instruction: Call Contract".to_owned(),
            format!("Program data: {}", base64_data),
            format!("Program {GATEWAY_PROGRAM_ID} success"),
        ];

        let msg = create_msg_counterpart(&event, 2);
        let signature = msg.message_id.raw_signature.into();
        let mut tx = tx_meta(logs);
        tx.err = Some(solana_sdk::transaction::TransactionError::AccountNotFound);

        assert_eq!(Vote::FailedOnChain, verify_message((&signature, &tx), &msg));
    }

    #[test]
    fn should_find_the_correct_index() {
        let (base64_data, event) = fixture_call_contract_log();
        let base64_data_different = "Y2FsbCBjb250cmFjdF9fXw== 6NGe5cm7PkXHz/g8V2VdRg0nU0l7R48x8lll4s0Clz0= xtlu5J3pLn7c4BhqnNSrP1wDZK/pQOJVCYbk6sroJhY= ZXRoZXJldW0= MHgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBhMGRlYWUyYzVlYzU0YTFkNmU0M2VhODU2YjI3N2RkMTExNjVhYjRk 8J+QqvCfkKrwn5Cq8J+Qqg==";
        assert_ne!(base64_data_different, base64_data);
        let logs = vec![
            format!("Program {GATEWAY_PROGRAM_ID} invoke [1]"),
            "Program log: Instruction: Call Contract".to_owned(),
            format!("Program data: {}", base64_data_different),
            format!("Program {GATEWAY_PROGRAM_ID} failed"), // Invocation 1 fails
            format!("Program {GATEWAY_PROGRAM_ID} invoke [1]"),
            "Program log: Instruction: Call Contract".to_owned(),
            format!("Program data: {}", base64_data),
            format!("Program {GATEWAY_PROGRAM_ID} success"), // Invocation 1 succeeds
            format!("Program {GATEWAY_PROGRAM_ID} invoke [1]"),
            "Program log: Instruction: Call Contract".to_owned(),
            format!("Program data: {}", base64_data_different),
            format!("Program {GATEWAY_PROGRAM_ID} failed"), // Invocation 1 fails
        ];

        let msg = create_msg_counterpart(&event, 6);
        let signature = msg.message_id.raw_signature.into();
        let tx = tx_meta(logs);

        assert_eq!(
            Vote::SucceededOnChain,
            verify_message((&signature, &tx), &msg)
        );
    }

    const GATEWAY_PROGRAM_ID: Pubkey = axelar_solana_gateway::ID;
    const RAW_SIGNATURE: [u8; 64] = [42; 64];

    fn fixture_call_contract_log() -> (String, CallContractEvent) {
        // this is a `CallContract` extract form other unittests
        let base64_data = "Y2FsbCBjb250cmFjdF9fXw== 6NGe5cm7PkXHz/g8V2VdRg0nU0l7R48x8lll4s0Clz0= xtlu5J3pLn7c4BhqnNSrP1wDZK/pQOJVCYbk6sroJhY= ZXRoZXJldW0= MHgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA2YzIwNjAzYzdiODc2NjgyYzEyMTczYmRlZjlhMWRjYTUyOGYxNGZk 8J+QqvCfkKrwn5Cq8J+Qqg==";
        // Simple `CallContract` fixture
        let event = CallContractEvent {
            sender_key: Pubkey::from_str("GfpyaXoJrd9XHHRehAPCGETie3wpM8xDxscAUoC12Cxt").unwrap(),
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

    fn create_msg_counterpart(event: &CallContractEvent, event_index: u32) -> Message {
        let msg = Message {
            message_id: axelar_wasm_std::msg_id::Base58SolanaTxSignatureAndEventIndex {
                raw_signature: RAW_SIGNATURE,
                event_index,
            },
            destination_address: event.destination_contract_address.clone(),
            destination_chain: event.destination_chain.clone().parse().unwrap(),
            source_address: event.sender_key,
            payload_hash: event.payload_hash.into(),
        };
        msg
    }

    fn fixture_success_call_contract_tx_data() -> (
        (Signature, UiTransactionStatusMeta),
        CallContractEvent,
        Message,
    ) {
        let (base64_data, event) = fixture_call_contract_log();
        let logs = vec![
            format!("Program {GATEWAY_PROGRAM_ID} invoke [1]"), // Invocation 1 starts
            "Program log: Instruction: Call Contract".to_owned(),
            format!("Program data: {}", base64_data),
            format!("Program {GATEWAY_PROGRAM_ID} success"), // Invocation 1 succeeds
        ];

        let msg = create_msg_counterpart(&event, 2);
        let signature = msg.message_id.raw_signature.into();

        ((signature, tx_meta(logs)), event, msg)
    }

    fn fixture_bad_gateway_call_contract_tx_data() -> (
        (Signature, UiTransactionStatusMeta),
        CallContractEvent,
        Message,
    ) {
        let bad_gateway = Pubkey::new_unique();

        let (base64_data, event) = fixture_call_contract_log();
        let logs = vec![
            format!("Program {bad_gateway} invoke [1]"), // Invocation 1 starts
            "Program log: Instruction: Call Contract".to_owned(),
            format!("Program data: {}", base64_data),
            format!("Program {bad_gateway} success"), // Invocation 1 succeeds
        ];

        let msg = create_msg_counterpart(&event, 2);
        let signature = msg.message_id.raw_signature.into();

        ((signature, tx_meta(logs)), event, msg)
    }

    fn tx_meta(logs: Vec<String>) -> UiTransactionStatusMeta {
        UiTransactionStatusMeta {
            err: None,
            status: Ok(()),
            fee: 0,
            pre_balances: vec![0],
            post_balances: vec![0],
            inner_instructions: OptionSerializer::None,
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
