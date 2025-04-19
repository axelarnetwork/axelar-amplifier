use axelar_wasm_std::voting::Vote;
use clarity::vm::types::{
    BufferLength, PrincipalData, SequenceSubtype, StringSubtype, TupleTypeSignature, TypeSignature,
    Value,
};
use clarity::vm::ClarityName;

use crate::handlers::stacks_verify_msg::Message;
use crate::handlers::stacks_verify_verifier_set::VerifierSetConfirmation;
use crate::stacks::error::Error;
use crate::stacks::http_client::{Transaction, TransactionEvents};
use crate::stacks::WeightedSigners;
use crate::types::Hash;

const PRINT_TOPIC: &str = "print";

const CONTRACT_CALL_TYPE: &str = "contract-call";
const SIGNERS_ROTATED_TYPE: &str = "signers-rotated";

impl Message {
    fn eq_event(
        &self,
        event: &TransactionEvents,
        new_payload_hash: Option<Hash>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let contract_log = event.contract_log.as_ref().ok_or(Error::PropertyEmpty)?;

        if contract_log.topic != PRINT_TOPIC {
            return Ok(false);
        }

        let tuple_type_signature = TupleTypeSignature::try_from(vec![
            (
                ClarityName::from("type"),
                TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                    BufferLength::try_from(13u32)?,
                ))),
            ),
            (ClarityName::from("sender"), TypeSignature::PrincipalType),
            (
                ClarityName::from("destination-chain"),
                TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                    BufferLength::try_from(20u32)?,
                ))),
            ),
            (
                ClarityName::from("destination-contract-address"),
                TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                    BufferLength::try_from(128u32)?,
                ))),
            ),
            (
                ClarityName::from("payload-hash"),
                TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                    32u32,
                )?)),
            ),
        ])?;

        let hex = contract_log
            .value
            .hex
            .strip_prefix("0x")
            .ok_or(Error::PropertyEmpty)?;

        let value =
            Value::try_deserialize_hex(hex, &TypeSignature::TupleType(tuple_type_signature), true)?;

        if let Value::Tuple(data) = value {
            if !data.get("type")?.eq(&Value::string_ascii_from_bytes(
                CONTRACT_CALL_TYPE.as_bytes().to_vec(),
            )?) {
                return Ok(false);
            }

            if !data
                .get("sender")?
                .eq(&Value::from(self.source_address.clone()))
            {
                return Ok(false);
            }

            if !data
                .get("destination-chain")?
                .eq(&Value::string_ascii_from_bytes(
                    self.destination_chain.as_ref().as_bytes().to_vec(),
                )?)
            {
                return Ok(false);
            }

            if !data
                .get("destination-contract-address")?
                .eq(&Value::string_ascii_from_bytes(
                    self.destination_address.as_bytes().to_vec(),
                )?)
            {
                return Ok(false);
            }

            if let Some(new_payload_hash) = new_payload_hash {
                if new_payload_hash != self.payload_hash {
                    return Ok(false);
                }
            } else if !data
                .get("payload-hash")?
                .eq(&Value::buff_from(self.payload_hash.as_bytes().to_vec())?)
            {
                return Ok(false);
            }

            return Ok(true);
        }

        Ok(false)
    }
}

impl VerifierSetConfirmation {
    fn eq_event(&self, event: &TransactionEvents) -> Result<bool, Box<dyn std::error::Error>> {
        let contract_log = event.contract_log.as_ref().ok_or(Error::PropertyEmpty)?;

        if contract_log.topic != PRINT_TOPIC {
            return Ok(false);
        }

        let tuple_type_signature = TupleTypeSignature::try_from(vec![
            (
                ClarityName::from("type"),
                TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                    BufferLength::try_from(15u32)?,
                ))),
            ),
            (
                ClarityName::from("signers-hash"),
                TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                    32u32,
                )?)),
            ),
        ])?;

        let hex = contract_log
            .value
            .hex
            .strip_prefix("0x")
            .ok_or(Error::PropertyEmpty)?;

        let value =
            Value::try_deserialize_hex(hex, &TypeSignature::TupleType(tuple_type_signature), true)?;

        if let Value::Tuple(data) = value {
            if !data.get("type")?.eq(&Value::string_ascii_from_bytes(
                SIGNERS_ROTATED_TYPE.as_bytes().to_vec(),
            )?) {
                return Ok(false);
            }

            let weighted_signers = WeightedSigners::try_from(&self.verifier_set)?;

            let hash = weighted_signers.hash();

            if !data
                .get("signers-hash")?
                .eq(&Value::buff_from(hash?.to_vec())?)
            {
                return Ok(false);
            }

            return Ok(true);
        }

        Ok(false)
    }
}

fn find_event<'a>(
    transaction: &'a Transaction,
    gateway_address: &PrincipalData,
    log_index: u64,
) -> Option<&'a TransactionEvents> {
    let event = transaction
        .events
        .iter()
        .find(|el| el.event_index == log_index)?;

    if !event
        .contract_log
        .as_ref()?
        .contract_id
        .eq(&gateway_address.to_string())
    {
        return None;
    }

    Some(event)
}

pub fn verify_message(
    gateway_address: &PrincipalData,
    transaction: &Transaction,
    message: &Message,
) -> Vote {
    if message.message_id.tx_hash != transaction.tx_id.as_bytes() {
        return Vote::NotFound;
    }

    match find_event(transaction, gateway_address, message.message_id.event_index) {
        Some(event) if message.eq_event(event, None).unwrap_or(false) => Vote::SucceededOnChain,
        _ => Vote::NotFound,
    }
}

pub fn verify_verifier_set(
    gateway_address: &PrincipalData,
    transaction: &Transaction,
    verifier_set: VerifierSetConfirmation,
) -> Vote {
    if verifier_set.message_id.tx_hash != transaction.tx_id.as_bytes() {
        return Vote::NotFound;
    }

    match find_event(
        transaction,
        gateway_address,
        verifier_set.message_id.event_index,
    ) {
        Some(event) if verifier_set.eq_event(event).unwrap_or(false) => Vote::SucceededOnChain,
        _ => Vote::NotFound,
    }
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelar_wasm_std::voting::Vote;
    use clarity::vm::types::{PrincipalData, TupleData};
    use clarity::vm::{ClarityName, Value};
    use cosmwasm_std::{HexBinary, Uint128};
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ecdsa_test_data};
    use tokio::test as async_test;

    use crate::handlers::stacks_verify_msg::Message;
    use crate::handlers::stacks_verify_verifier_set::VerifierSetConfirmation;
    use crate::stacks::http_client::{
        ContractLog, ContractLogValue, Transaction, TransactionEvents,
    };
    use crate::stacks::verifier::{verify_message, verify_verifier_set, SIGNERS_ROTATED_TYPE};
    use crate::types::Hash;

    // test verify message
    #[async_test]
    async fn should_not_verify_tx_id_does_not_match() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.message_id.tx_hash = Hash::random().into();

        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[async_test]
    async fn should_not_verify_no_log_for_event_index() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.message_id.event_index = 2;

        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[async_test]
    async fn should_not_verify_event_index_does_not_match() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.message_id.event_index = 0;

        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[async_test]
    async fn should_not_verify_not_gateway() {
        let (gateway_address, mut tx, msg) = get_matching_msg_and_tx();

        let transaction_events = tx.events.get_mut(1).unwrap();
        let contract_call = transaction_events.contract_log.as_mut().unwrap();

        contract_call.contract_id = "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM".to_string();

        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[async_test]
    async fn should_not_verify_invalid_topic() {
        let (gateway_address, mut tx, msg) = get_matching_msg_and_tx();

        let transaction_events = tx.events.get_mut(1).unwrap();
        let contract_call = transaction_events.contract_log.as_mut().unwrap();

        contract_call.topic = "other".to_string();

        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[async_test]
    async fn should_not_verify_invalid_type() {
        let (gateway_address, mut tx, msg) = get_matching_msg_and_tx();

        let transaction_events = tx.events.get_mut(1).unwrap();
        let contract_call = transaction_events.contract_log.as_mut().unwrap();

        // Remove 'call' as hex from `contract-call` data
        contract_call.value.hex = contract_call
            .value
            .hex
            .strip_suffix("63616c6c")
            .unwrap()
            .to_string();

        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[async_test]
    async fn should_not_verify_invalid_sender() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.source_address =
            PrincipalData::parse("SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.axelar-gateway")
                .unwrap();

        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[async_test]
    async fn should_not_verify_invalid_destination_chain() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.destination_chain = "other".parse().unwrap();

        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[async_test]
    async fn should_not_verify_invalid_destination_address() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.destination_address = "other".parse().unwrap();

        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[async_test]
    async fn should_not_verify_invalid_payload_hash() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.payload_hash = "0xaa38573718f5cd6d7e5a90adcdebd28b097f99574ad6febffea9a40adb17f4aa"
            .parse()
            .unwrap();

        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[async_test]
    async fn should_verify_msg() {
        let (gateway_address, tx, msg) = get_matching_msg_and_tx();

        assert_eq!(
            verify_message(&gateway_address, &tx, &msg),
            Vote::SucceededOnChain
        );
    }

    // test verify worker set
    #[test]
    fn should_not_verify_verifier_set_if_tx_id_does_not_match() {
        let (gateway_address, tx, mut verifier_set) = get_matching_verifier_set_and_tx();

        verifier_set.message_id.tx_hash = Hash::random().into();

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx, verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_no_log_for_event_index() {
        let (gateway_address, tx, mut verifier_set) = get_matching_verifier_set_and_tx();

        verifier_set.message_id.event_index = 2;

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx, verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_event_index_does_not_match() {
        let (gateway_address, tx, mut verifier_set) = get_matching_verifier_set_and_tx();

        verifier_set.message_id.event_index = 0;

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx, verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_not_from_gateway() {
        let (gateway_address, mut tx, verifier_set) = get_matching_verifier_set_and_tx();

        let transaction_events = tx.events.get_mut(1).unwrap();
        let contract_call = transaction_events.contract_log.as_mut().unwrap();

        contract_call.contract_id = "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM".to_string();

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx, verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_invalid_topic() {
        let (gateway_address, mut tx, verifier_set) = get_matching_verifier_set_and_tx();

        let transaction_events = tx.events.get_mut(1).unwrap();
        let contract_call = transaction_events.contract_log.as_mut().unwrap();

        contract_call.topic = "other".to_string();

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx, verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_invalid_type() {
        let (gateway_address, mut tx, verifier_set) = get_matching_verifier_set_and_tx();

        let transaction_events = tx.events.get_mut(1).unwrap();
        let signers_rotated = transaction_events.contract_log.as_mut().unwrap();

        // Remove 'rotated' as hex from `signers-rotated` data
        signers_rotated.value.hex = signers_rotated
            .value
            .hex
            .strip_suffix("726f7461746564")
            .unwrap()
            .to_string();

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx, verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_worker_set_if_verifier_set_does_not_match() {
        let (gateway_address, tx, mut verifier_set) = get_matching_verifier_set_and_tx();

        verifier_set.verifier_set.threshold = Uint128::from(10u128);
        assert_eq!(
            verify_verifier_set(&gateway_address, &tx, verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_verify_verifier_set() {
        let (gateway_address, tx, verifier_set) = get_matching_verifier_set_and_tx();

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx, verifier_set),
            Vote::SucceededOnChain
        );
    }

    fn get_matching_msg_and_tx() -> (PrincipalData, Transaction, Message) {
        let gateway_address =
            PrincipalData::parse("SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.axelar-gateway")
                .unwrap();

        let message_id = HexTxHashAndEventIndex::new(Hash::random(), 1u64);

        let msg = Message {
            message_id: message_id.clone(),
            source_address: PrincipalData::parse("ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG")
                .unwrap(),
            destination_chain: "Destination".parse().unwrap(),
            destination_address: "0x123abc".to_string(),
            payload_hash: "0x9ed02951dbf029855b46b102cc960362732569e83d00a49a7575d7aed229890e"
                .parse()
                .unwrap(),
        };

        let wrong_event = TransactionEvents {
            event_index: 0,
            contract_log: None,
        };

        let event = TransactionEvents {
            event_index: 1,
            contract_log: Some(ContractLog {
                contract_id: gateway_address.to_string(),
                topic: "print".to_string(),
                value: ContractLogValue {
                    hex: "0x0c000000061164657374696e6174696f6e2d636861696e0d0000000b64657374696e6174696f6e1c64657374696e6174696f6e2d636f6e74726163742d616464726573730d000000083078313233616263077061796c6f61640200000029535431534a3344544535444e375835345944483544363452334243423641324147325a5138595044350c7061796c6f61642d6861736802000000209ed02951dbf029855b46b102cc960362732569e83d00a49a7575d7aed229890e0673656e646572051a99e2ec69ac5b6e67b4e26edd0e2c1c1a6b9bbd2304747970650d0000000d636f6e74726163742d63616c6c".to_string(),
                },
            }),
        };

        let transaction = Transaction {
            tx_id: message_id.tx_hash.into(),
            tx_status: "success".to_string(),
            events: vec![wrong_event, event],
            block_height: 10,
        };

        (gateway_address, transaction, msg)
    }

    fn get_matching_verifier_set_and_tx() -> (PrincipalData, Transaction, VerifierSetConfirmation) {
        let gateway_address =
            PrincipalData::parse("SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.axelar-gateway")
                .unwrap();
        let message_id = HexTxHashAndEventIndex::new(Hash::random(), 1u64);

        let mut verifier_set_confirmation = VerifierSetConfirmation {
            message_id: message_id.clone(),
            verifier_set: build_verifier_set(KeyType::Ecdsa, &ecdsa_test_data::signers()),
        };
        verifier_set_confirmation.verifier_set.created_at = 5;

        let wrong_event = TransactionEvents {
            event_index: 0,
            contract_log: None,
        };

        let signers_hash =
            HexBinary::from_hex("adea9dbea0104ab812b94209a9f3262f0f203a748d8f27e508f8457693637c76")
                .unwrap();

        let value = Value::from(
            TupleData::from_data(vec![
                (
                    ClarityName::from("signers-hash"),
                    Value::buff_from(signers_hash.to_vec()).unwrap(),
                ),
                (
                    ClarityName::from("type"),
                    Value::string_ascii_from_bytes(SIGNERS_ROTATED_TYPE.as_bytes().to_vec())
                        .unwrap(),
                ),
            ])
            .unwrap(),
        );

        let event = TransactionEvents {
            event_index: 1,
            contract_log: Some(ContractLog {
                contract_id: gateway_address.to_string(),
                topic: "print".to_string(),
                value: ContractLogValue {
                    hex: format!("0x{}", value.serialize_to_hex().unwrap()),
                },
            }),
        };

        let transaction = Transaction {
            tx_id: message_id.tx_hash.into(),
            tx_status: "success".to_string(),
            events: vec![wrong_event, event],
            block_height: 10,
        };

        (gateway_address, transaction, verifier_set_confirmation)
    }
}
