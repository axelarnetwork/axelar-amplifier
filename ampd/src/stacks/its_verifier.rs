use clarity::vm::types::{
    BufferLength, PrincipalData, SequenceSubtype, StringSubtype, TupleTypeSignature, TypeSignature,
};
use clarity::vm::{ClarityName, Value};

use crate::handlers::stacks_verify_msg::Message;
use crate::stacks::error::Error;
use crate::stacks::http_client::TransactionEvents;
use crate::stacks::verifier::{CONTRACT_CALL_TYPE, PRINT_TOPIC};

const MESSAGE_TYPE_INTERCHAIN_TRANSFER: u128 = 0;
const MESSAGE_TYPE_DEPLOY_INTERCHAIN_TOKEN: u128 = 1;
const MESSAGE_TYPE_DEPLOY_TOKEN_MANAGER: u128 = 2;
const MESSAGE_TYPE_SEND_TO_HUB: u128 = 3;

impl Message {
    pub fn eq_its_hub_event(
        &self,
        event: &TransactionEvents,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let contract_log = event.contract_log.as_ref().ok_or(Error::PropertyEmpty)?;

        if contract_log.topic != PRINT_TOPIC {
            return Ok(false);
        }

        let tuple_type_signature = TupleTypeSignature::try_from(vec![
            (ClarityName::from("type"), TypeSignature::UIntType),
            (
                ClarityName::from("destination-chain"),
                TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                    18u32,
                )?)),
            ),
            (
                ClarityName::from("payload"),
                TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                    10240u32,
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
            // All messages should go through ITS hub
            if !data.get("type")?.eq(&Value::UInt(MESSAGE_TYPE_SEND_TO_HUB)) {
                return Ok(false);
            }

            let subtuple_type_signature = TupleTypeSignature::try_from(vec![(
                ClarityName::from("type"),
                TypeSignature::UIntType,
            )])?;

            let original_value = Value::try_deserialize_hex(
                hex,
                &TypeSignature::TupleType(subtuple_type_signature),
                true,
            )?;

            // Unwrapp its payload
            if let Value::Tuple(new_data) = original_value {
                if new_data.get("type")?.eq(&Value::UInt(MESSAGE_TYPE_INTERCHAIN_TRANSFER)) {
                    // TODO: Decode and ABI encode this payload
                } else if new_data.get("type")?.eq(&Value::UInt(MESSAGE_TYPE_DEPLOY_INTERCHAIN_TOKEN)) {
                    // TODO: Decode and ABI encode this payload
                } else if new_data.get("type")?.eq(&Value::UInt(MESSAGE_TYPE_DEPLOY_TOKEN_MANAGER)) {
                    // TODO: Decode and ABI encode this payload
                }
            }

            return Ok(false);
        }

        Ok(false)
    }

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
