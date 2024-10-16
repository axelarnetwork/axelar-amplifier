use axelar_wasm_std::voting::Vote;
use clarity::vm::types::{
    BufferLength, PrincipalData, SequenceSubtype, StringSubtype, TupleTypeSignature, TypeSignature,
    Value,
};
use clarity::vm::ClarityName;

use crate::handlers::stacks_verify_msg::Message;
use crate::stacks::error::Error;
use crate::stacks::http_client::{Transaction, TransactionEvents};

const PRINT_TOPIC: &str = "print";

const CONTRACT_CALL_TYPE: &str = "contract-call";

impl Message {
    fn eq_event(&self, event: &TransactionEvents) -> Result<bool, Box<dyn std::error::Error>> {
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
                TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                    18u32,
                )?)),
            ),
            (
                ClarityName::from("destination-contract-address"),
                TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                    96u32,
                )?)),
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

            if !data.get("sender")?.eq(&Value::from(PrincipalData::parse(
                self.source_address.as_str(),
            )?)) {
                return Ok(false);
            }

            if !data.get("destination-chain")?.eq(&Value::buff_from(
                self.destination_chain.as_ref().as_bytes().to_vec(),
            )?) {
                return Ok(false);
            }

            if !data
                .get("destination-contract-address")?
                .eq(&Value::buff_from(
                    self.destination_address.as_bytes().to_vec(),
                )?)
            {
                return Ok(false);
            }

            if !data
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

fn find_event<'a>(
    transaction: &'a Transaction,
    gateway_address: &String,
    log_index: u32,
) -> Option<&'a TransactionEvents> {
    let event = transaction
        .events
        .iter()
        .find(|el| el.event_index == log_index)?;

    if !event.contract_log.as_ref()?.contract_id.eq(gateway_address) {
        return None;
    }

    Some(event)
}

pub fn verify_message(
    gateway_address: &String,
    transaction: &Transaction,
    message: &Message,
) -> Vote {
    if message.tx_id != transaction.tx_id {
        return Vote::NotFound;
    }

    match find_event(transaction, gateway_address, message.event_index) {
        Some(event) if message.eq_event(event).unwrap_or(false) => Vote::SucceededOnChain,
        _ => Vote::NotFound,
    }
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::voting::Vote;

    use crate::handlers::stacks_verify_msg::Message;
    use crate::stacks::http_client::{
        ContractLog, ContractLogValue, Transaction, TransactionEvents,
    };
    use crate::stacks::verifier::verify_message;

    // test verify message
    #[test]
    fn should_not_verify_tx_id_does_not_match() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.tx_id = "ffaf64de66510723f2efbacd7ead3c4f8c856aed1afc2cb30254552aeda47313"
            .parse()
            .unwrap();
        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[test]
    fn should_not_verify_no_log_for_event_index() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.event_index = 2;

        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[test]
    fn should_not_verify_event_index_does_not_match() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.event_index = 0;

        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[test]
    fn should_not_verify_not_gateway() {
        let (gateway_address, mut tx, msg) = get_matching_msg_and_tx();

        let transaction_events = tx.events.get_mut(1).unwrap();
        let contract_call = transaction_events.contract_log.as_mut().unwrap();

        contract_call.contract_id = "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM".to_string();

        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[test]
    fn should_not_verify_invalid_topic() {
        let (gateway_address, mut tx, msg) = get_matching_msg_and_tx();

        let transaction_events = tx.events.get_mut(1).unwrap();
        let contract_call = transaction_events.contract_log.as_mut().unwrap();

        contract_call.topic = "other".to_string();

        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[test]
    fn should_not_verify_invalid_type() {
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

    #[test]
    fn should_not_verify_invalid_sender() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.source_address = "SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.axelar-gateway".to_string();

        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[test]
    fn should_not_verify_invalid_destination_chain() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.destination_chain = "other".parse().unwrap();

        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[test]
    fn should_not_verify_invalid_destination_address() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.destination_address = "other".parse().unwrap();

        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[test]
    fn should_not_verify_invalid_payload_hash() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.payload_hash = "0xaa38573718f5cd6d7e5a90adcdebd28b097f99574ad6febffea9a40adb17f4aa"
            .parse()
            .unwrap();

        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[test]
    fn should_verify_msg() {
        let (gateway_address, tx, msg) = get_matching_msg_and_tx();

        assert_eq!(
            verify_message(&gateway_address, &tx, &msg),
            Vote::SucceededOnChain
        );
    }

    fn get_matching_msg_and_tx() -> (String, Transaction, Message) {
        let gateway_address = "SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.axelar-gateway";
        let tx_id = "0xee0049faf8dde5507418140ed72bd64f73cc001b08de98e0c16a3a8d9f2c38cf"
            .parse()
            .unwrap();

        let msg = Message {
            tx_id,
            event_index: 1,
            source_address: "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM".to_string(),
            destination_chain: "ethereum".parse().unwrap(),
            destination_address: "0x043E105189e15AC72252CFEF898EC3841A4A0561".to_string(),
            payload_hash: "0x0338573718f5cd6d7e5a90adcdebd28b097f99574ad6febffea9a40adb17f46d"
                .parse()
                .unwrap(),
        };

        let wrong_event = TransactionEvents {
            event_index: 0,
            tx_id: tx_id.to_string(),
            contract_log: None,
        };

        let event = TransactionEvents {
            event_index: 1,
            tx_id: tx_id.to_string(),
            contract_log: Some(ContractLog {
                contract_id: gateway_address.to_string(),
                topic: "print".to_string(),
                value: ContractLogValue {
                    hex: "0x0c000000061164657374696e6174696f6e2d636861696e0200000008657468657265756d1c64657374696e6174696f6e2d636f6e74726163742d61646472657373020000002a307830343345313035313839653135414337323235324346454638393845433338343141344130353631077061796c6f616402000000196c6f72656d697073756d20646f6c6f722073697420616d65740c7061796c6f61642d6861736802000000200338573718f5cd6d7e5a90adcdebd28b097f99574ad6febffea9a40adb17f46d0673656e646572051a6d78de7b0625dfbfc16c3a8a5735f6dc3dc3f2ce04747970650d0000000d636f6e74726163742d63616c6c".to_string(),
                }
            }),
        };

        let transaction = Transaction {
            tx_id,
            nonce: 1,
            sender_address: "whatever".to_string(),
            tx_status: "success".to_string(),
            events: vec![wrong_event, event],
        };

        (gateway_address.to_string(), transaction, msg)
    }
}
