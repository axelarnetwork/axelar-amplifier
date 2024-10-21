use crate::handlers::stacks_verify_msg::Message;
use crate::stacks::error::Error;
use crate::stacks::http_client::TransactionEvents;
use crate::stacks::verifier::{CONTRACT_CALL_TYPE, PRINT_TOPIC};
use axelar_wasm_std::hash::Hash;
use clarity::codec::StacksMessageCodec;
use clarity::vm::types::{
    BufferLength, PrincipalData, SequenceSubtype, StringSubtype, TupleData, TupleTypeSignature,
    TypeSignature,
};
use clarity::vm::{ClarityName, Value};
use ethers_core::abi::{encode, Token};
use sha3::{Digest, Keccak256};

const MESSAGE_TYPE_INTERCHAIN_TRANSFER: u128 = 0;
const MESSAGE_TYPE_DEPLOY_INTERCHAIN_TOKEN: u128 = 1;
const MESSAGE_TYPE_DEPLOY_TOKEN_MANAGER: u128 = 2;
const MESSAGE_TYPE_SEND_TO_HUB: u128 = 3;

fn get_payload_from_contract_call_event(
    event: &TransactionEvents,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let contract_log = event.contract_log.as_ref().ok_or(Error::PropertyEmpty)?;

    let contract_call_signature = TupleTypeSignature::try_from(vec![(
        ClarityName::from("payload"),
        TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
            10240u32,
        )?)),
    )])?;

    let hex = contract_log
        .value
        .hex
        .strip_prefix("0x")
        .ok_or(Error::PropertyEmpty)?;

    let contract_call_value = Value::try_deserialize_hex(
        hex,
        &TypeSignature::TupleType(contract_call_signature),
        true,
    )?;

    let payload = contract_call_value
        .expect_tuple()?
        .get_owned("payload")?
        .expect_buff(10240)?;

    Ok(payload)
}

fn get_its_hub_call_params(
    event: &TransactionEvents,
) -> Result<TupleData, Box<dyn std::error::Error>> {
    let payload = get_payload_from_contract_call_event(event)?;

    let its_send_to_hub_signature = TupleTypeSignature::try_from(vec![
        (ClarityName::from("type"), TypeSignature::UIntType),
        (
            ClarityName::from("destination-chain"),
            TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                BufferLength::try_from(18u32)?,
            ))),
        ),
        (
            ClarityName::from("payload"),
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                10240u32,
            )?)),
        ),
    ])?;

    let its_hub_value = Value::try_deserialize_bytes(
        &payload,
        &TypeSignature::TupleType(its_send_to_hub_signature),
        true,
    )?
    .expect_tuple()?;

    Ok(its_hub_value)
}

fn get_its_interchain_transfer_abi_payload(
    payload: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let tuple_type_signature = TupleTypeSignature::try_from(vec![
        (
            ClarityName::from("token-id"),
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                32u32,
            )?)),
        ),
        (
            ClarityName::from("source-address"),
            TypeSignature::PrincipalType,
        ),
        (
            ClarityName::from("destination-chain"),
            TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                BufferLength::try_from(18u32)?,
            ))),
        ),
        (
            ClarityName::from("destination-address"),
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                100u32,
            )?)),
        ),
        (ClarityName::from("amount"), TypeSignature::UIntType),
        (
            ClarityName::from("data"),
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                1024u32,
            )?)),
        ),
    ])?;

    let mut original_value = Value::try_deserialize_bytes(
        &payload,
        &TypeSignature::TupleType(tuple_type_signature),
        true,
    )?
    .expect_tuple()?;

    let abi_payload = encode(&[
        Token::Uint(MESSAGE_TYPE_INTERCHAIN_TRANSFER.into()),
        Token::FixedBytes(
            original_value
                .data_map
                .remove("token-id")
                .ok_or(Error::InvalidCall)?
                .expect_buff(32)?,
        ),
        Token::Bytes(
            original_value
                .data_map
                .remove("source-address")
                .ok_or(Error::InvalidCall)?
                .expect_principal()?
                .serialize_to_vec(),
        ),
        Token::Bytes(
            original_value
                .data_map
                .remove("destination-address")
                .ok_or(Error::InvalidCall)?
                .expect_buff(100)?,
        ),
        Token::Uint(
            original_value
                .data_map
                .remove("amount")
                .ok_or(Error::InvalidCall)?
                .expect_u128()?
                .into(),
        ),
        Token::Bytes(
            original_value
                .data_map
                .remove("data")
                .ok_or(Error::InvalidCall)?
                .expect_buff(1024)?,
        ),
    ]);

    Ok(abi_payload)
}

impl Message {
    pub fn eq_its_hub_event(
        &self,
        event: &TransactionEvents,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let tuple_data = get_its_hub_call_params(event)?;

        // All messages should go through ITS hub
        if !tuple_data
            .get("type")?
            .eq(&Value::UInt(MESSAGE_TYPE_SEND_TO_HUB))
        {
            return Ok(false);
        }

        let destination_chain = tuple_data
            .get("destination-chain")?
            .clone()
            .expect_ascii()?;
        let payload = tuple_data.get_owned("payload")?.expect_buff(10240)?;

        let subtuple_type_signature = TupleTypeSignature::try_from(vec![(
            ClarityName::from("type"),
            TypeSignature::UIntType,
        )])?;

        let original_its_call = Value::try_deserialize_bytes(
            &payload,
            &TypeSignature::TupleType(subtuple_type_signature),
            true,
        )?
        .expect_tuple()?;

        let its_type = original_its_call.get_owned("type")?.expect_u128()?;

        let abi_payload = match its_type {
            MESSAGE_TYPE_INTERCHAIN_TRANSFER => get_its_interchain_transfer_abi_payload(payload),
            // TODO: Handle other cases
            // MESSAGE_TYPE_DEPLOY_INTERCHAIN_TOKEN => {}
            // MESSAGE_TYPE_DEPLOY_TOKEN_MANAGER => {}
            _ => {
                return Err(Error::InvalidCall.into());
            }
        }?;

        // Convert to ITS payload and use its hash to verify the message
        let abi_payload = encode(&[
            Token::Uint(MESSAGE_TYPE_SEND_TO_HUB.into()),
            Token::String(destination_chain),
            Token::Bytes(abi_payload),
        ]);

        let payload_hash: Hash = Keccak256::digest(abi_payload).into();

        self.eq_event(event, Some(payload_hash.into()))
    }

    // TODO:
    pub fn eq_its_verify_event(
        &self,
        event: &TransactionEvents,
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

#[cfg(test)]
mod tests {
    use axelar_wasm_std::voting::Vote;
    use router_api::ChainName;

    use crate::handlers::stacks_verify_msg::Message;
    use crate::stacks::http_client::{
        ContractLog, ContractLogValue, Transaction, TransactionEvents,
    };
    use crate::stacks::verifier::verify_message;

    // test verify message its hub
    #[test]
    fn should_not_verify_its_hub_invalid_payload_hash() {
        let (source_chain, gateway_address, its_address, tx, mut msg) =
            get_matching_its_hub_msg_and_tx();

        msg.payload_hash = "0xaa38573718f5cd6d7e5a90adcdebd28b097f99574ad6febffea9a40adb17f4aa"
            .parse()
            .unwrap();

        assert_eq!(
            verify_message(&source_chain, &gateway_address, &its_address, &tx, &msg),
            Vote::NotFound
        );
    }

    // // TODO:
    // #[test]
    // fn should_verify_msg_its_hub_interchain_transfer() {
    //     let (source_chain, gateway_address, its_address, tx, msg) =
    //         get_matching_its_hub_msg_and_tx();
    //
    //     assert_eq!(
    //         verify_message(&source_chain, &gateway_address, &its_address, &tx, &msg),
    //         Vote::SucceededOnChain
    //     );
    // }

    // test verify message its
    #[test]
    fn should_not_verify_its_invalid_payload_hash() {
        let (source_chain, gateway_address, its_address, tx, mut msg) =
            get_matching_its_verify_msg_and_tx();

        msg.payload_hash = "0xaa38573718f5cd6d7e5a90adcdebd28b097f99574ad6febffea9a40adb17f4aa"
            .parse()
            .unwrap();

        assert_eq!(
            verify_message(&source_chain, &gateway_address, &its_address, &tx, &msg),
            Vote::NotFound
        );
    }

    // TODO:
    // #[test]
    // fn should_verify_msg_its_interchain_transfer() {
    //     let (source_chain, gateway_address, its_address, tx, msg) =
    //         get_matching_its_verify_msg_and_tx();
    //
    //     assert_eq!(
    //         verify_message(&source_chain, &gateway_address, &its_address, &tx, &msg),
    //         Vote::SucceededOnChain
    //     );
    // }

    fn get_matching_its_hub_msg_and_tx() -> (ChainName, String, String, Transaction, Message) {
        let source_chain = "stacks";
        let gateway_address = "SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.axelar-gateway";
        let its_address = "ST2TFVBMRPS5SSNP98DQKQ5JNB2B6NZM91C4K3P7B.its";
        let tx_id = "0xee0049faf8dde5507418140ed72bd64f73cc001b08de98e0c16a3a8d9f2c38cf"
            .parse()
            .unwrap();

        let msg = Message {
            tx_id,
            event_index: 1,
            source_address: its_address.to_string(),
            destination_chain: "axelar".parse().unwrap(),
            destination_address: "axelartest".to_string(),
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

        (
            source_chain.parse().unwrap(),
            gateway_address.to_string(),
            its_address.to_string(),
            transaction,
            msg,
        )
    }

    fn get_matching_its_verify_msg_and_tx() -> (ChainName, String, String, Transaction, Message) {
        let source_chain = "stacks";
        let gateway_address = "SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.axelar-gateway";
        let its_address = "ST2TFVBMRPS5SSNP98DQKQ5JNB2B6NZM91C4K3P7B.its";
        let tx_id = "0xee0049faf8dde5507418140ed72bd64f73cc001b08de98e0c16a3a8d9f2c38cf"
            .parse()
            .unwrap();

        let msg = Message {
            tx_id,
            event_index: 1,
            source_address: its_address.to_string(),
            destination_chain: source_chain.parse().unwrap(),
            destination_address: its_address.to_string(),
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

        (
            source_chain.parse().unwrap(),
            gateway_address.to_string(),
            its_address.to_string(),
            transaction,
            msg,
        )
    }
}
