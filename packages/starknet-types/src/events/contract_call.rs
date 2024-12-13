use ethers_core::types::H256;
use starknet_core::types::Felt;
use starknet_core::utils::{parse_cairo_short_string, ParseCairoShortStringError};
use thiserror::Error;

use crate::events::EventType;
use crate::types::byte_array::{ByteArray, ByteArrayError};

/// This is the event emitted by the gateway cairo contract on Starknet,
/// when the call_contract method is called from a third party.
#[derive(Debug, PartialEq, Clone)]
pub struct ContractCallEvent {
    pub from_contract_addr: String,
    pub destination_address: String,
    pub destination_chain: String,
    pub source_address: Felt,
    pub payload_hash: H256,
}

/// An error, representing failure to convert/parse a starknet event
/// to some specific event.
#[derive(Error, Debug)]
pub enum ContractCallError {
    #[error("Invalid ContractCall event: {0}")]
    InvalidEvent(String),
    #[error("Cairo short string parse error: {0}")]
    Cairo(#[from] ParseCairoShortStringError),
    #[error("Failed felt conversion: {0}")]
    TryFromConversion(String),
    #[error("Event data/keys array index is out of bounds")]
    OutOfBound,
    #[error("ByteArray type error: {0}")]
    ByteArray(#[from] ByteArrayError),
}

impl TryFrom<starknet_core::types::Event> for ContractCallEvent {
    type Error = ContractCallError;

    fn try_from(starknet_event: starknet_core::types::Event) -> Result<Self, Self::Error> {
        if starknet_event.keys.len() != 2 {
            return Err(ContractCallError::InvalidEvent(
                "ContractCall should have exactly 2 event keys - event_type and destination_chain"
                    .to_owned(),
            ));
        }

        // first key is always the event type
        let event_type_felt = starknet_event.keys[0];
        if !matches!(
            EventType::parse(event_type_felt),
            Some(EventType::ContractCall)
        ) {
            return Err(ContractCallError::InvalidEvent(
                "not a ContractCall event".to_owned(),
            ));
        }

        // `event.from_address` is the contract address, which emitted the event
        let from_contract_addr = format!(
            "0x{}",
            hex::encode(starknet_event.from_address.to_bytes_be())
        );

        // destination_chain is the second key in the event keys list (the first key
        // defined from the event)
        //
        // This field, should not exceed 252 bits (a felt's length)
        let destination_chain = parse_cairo_short_string(&starknet_event.keys[1])?;

        // source_address represents the original caller of the `call_contract` gateway
        // method. It is the first field in data, by the order defined in the
        // event.
        let source_address = starknet_event.data[0];

        // destination_contract_address (ByteArray) is composed of FieldElements
        // from the second element to elemet X.
        let destination_address_chunks_count_felt = starknet_event.data[1];
        let da_chunks_count: usize = u8::try_from(destination_address_chunks_count_felt)
            .map_err(|err| ContractCallError::TryFromConversion(err.to_string()))?
            .into();

        // It's + 3, because we need to offset the 0th element, pending_word and
        // pending_word_count, in addition to all chunks (da_chunks_count_usize)
        let da_elements_start_index: usize = 1;
        let da_elements_end_index: usize = da_chunks_count.wrapping_add(3);
        let destination_address_byte_array: ByteArray = ByteArray::try_from(
            starknet_event
                .data
                .get(da_elements_start_index..=da_elements_end_index)
                .ok_or(ContractCallError::OutOfBound)?
                .to_vec(),
        )?;
        let destination_address = destination_address_byte_array.try_to_string()?;

        // payload_hash is a keccak256, which is a combination of two felts (chunks)
        // - first felt contains the 128 least significat bits (LSB)
        // - second felt contains the 128 most significat bits (MSG)
        let ph_chunk1_index: usize = da_elements_end_index.wrapping_add(1);
        let ph_chunk2_index: usize = ph_chunk1_index.wrapping_add(1);
        let mut payload_hash = [0; 32];
        let lsb: [u8; 32] = starknet_event
            .data
            .get(ph_chunk1_index)
            .ok_or(ContractCallError::InvalidEvent(
                "payload_hash chunk 1 out of range".to_owned(),
            ))?
            .to_bytes_be();
        let msb: [u8; 32] = starknet_event
            .data
            .get(ph_chunk2_index)
            .ok_or(ContractCallError::InvalidEvent(
                "payload_hash chunk 2 out of range".to_owned(),
            ))?
            .to_bytes_be();

        // most significat bits, go before least significant bits for u256 construction
        // check - https://docs.starknet.io/documentation/architecture_and_concepts/Smart_Contracts/serialization_of_Cairo_types/#serialization_in_u256_values
        payload_hash[..16].copy_from_slice(&msb[16..]);
        payload_hash[16..].copy_from_slice(&lsb[16..]);

        Ok(ContractCallEvent {
            from_contract_addr,
            destination_address,
            destination_chain,
            source_address,
            payload_hash: H256::from_slice(&payload_hash),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ethers_core::types::H256;
    use starknet_core::types::{Felt, FromStrError};
    use starknet_core::utils::starknet_keccak;

    use super::ContractCallEvent;
    use crate::events::contract_call::ContractCallError;
    use crate::types::byte_array::ByteArrayError;

    #[test]
    fn destination_address_chunks_offset_out_of_range() {
        let mut starknet_event = get_dummy_event();
        // longer chunk, which offsets the destination_address byte array out of range
        starknet_event.data[1] =
            Felt::from_str("0x0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();

        let event = ContractCallEvent::try_from(starknet_event).unwrap_err();
        assert!(matches!(
            event,
            ContractCallError::ByteArray(ByteArrayError::ParsingFelt(_))
        ));
    }

    #[test]
    fn destination_address_chunks_count_too_long() {
        let mut starknet_event = get_dummy_event();
        // too long for u32
        starknet_event.data[1] = Felt::MAX;

        let event = ContractCallEvent::try_from(starknet_event).unwrap_err();
        assert!(matches!(event, ContractCallError::TryFromConversion(_)));
    }

    #[test]
    fn invalid_dest_chain() {
        let mut starknet_event = get_dummy_event();
        // too long for Cairo long string too long
        starknet_event.keys[1] = Felt::MAX;

        let event = ContractCallEvent::try_from(starknet_event).unwrap_err();
        assert!(matches!(event, ContractCallError::Cairo(_)));
    }

    #[test]
    fn more_than_2_keys() {
        // the payload is the word "hello"
        let mut starknet_event = get_dummy_event();
        starknet_event
            .keys
            .push(starknet_keccak("additional_element".as_bytes()));

        let event = ContractCallEvent::try_from(starknet_event).unwrap_err();
        assert!(matches!(event, ContractCallError::InvalidEvent(_)));
    }

    #[test]
    fn wrong_event_type() {
        // the payload is the word "hello"
        let mut starknet_event = get_dummy_event();
        starknet_event.keys[0] = starknet_keccak("NOTContractCall".as_bytes());

        let event = ContractCallEvent::try_from(starknet_event).unwrap_err();
        assert!(matches!(event, ContractCallError::InvalidEvent(_)));
    }

    #[test]
    fn valid_call_contract_event() {
        // the payload is the word "hello"
        let starknet_event = get_dummy_event();
        let event = ContractCallEvent::try_from(starknet_event).unwrap();

        assert_eq!(
            event,
            ContractCallEvent {
                from_contract_addr: String::from(
                    "0x035410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439e"
                ),
                destination_address: String::from("hello"),
                destination_chain: String::from("destination_chain"),
                source_address: Felt::from_str(
                    "0x00b3ff441a68610b30fd5e2abbf3a1548eb6ba6f3559f2862bf2dc757e5828ca"
                )
                .unwrap(),
                payload_hash: H256::from_slice(&[
                    28, 138, 255, 149, 6, 133, 194, 237, 75, 195, 23, 79, 52, 114, 40, 123, 86,
                    217, 81, 123, 156, 148, 129, 39, 49, 154, 9, 167, 163, 109, 234, 200
                ])
            }
        );
    }

    fn get_dummy_event() -> starknet_core::types::Event {
        // "hello" as payload
        // "hello" as destination address
        // "some_contract_address" as source address
        // "destination_chain" as destination_chain
        let event_data: Result<Vec<Felt>, FromStrError> = vec![
            "0xb3ff441a68610b30fd5e2abbf3a1548eb6ba6f3559f2862bf2dc757e5828ca", // the caller addr
            "0x0000000000000000000000000000000000000000000000000000000000000000", // 0 data
            "0x00000000000000000000000000000000000000000000000000000068656c6c6f", // "hello"
            "0x0000000000000000000000000000000000000000000000000000000000000005", // 5 bytes
            "0x0000000000000000000000000000000056d9517b9c948127319a09a7a36deac8", // keccak256(hello)
            "0x000000000000000000000000000000001c8aff950685c2ed4bc3174f3472287b",
            "0x0000000000000000000000000000000000000000000000000000000000000005", // 5 bytes
            "0x0000000000000000000000000000000000000000000000000000000000000068", // h
            "0x0000000000000000000000000000000000000000000000000000000000000065", // e
            "0x000000000000000000000000000000000000000000000000000000000000006c", // l
            "0x000000000000000000000000000000000000000000000000000000000000006c", // l
            "0x000000000000000000000000000000000000000000000000000000000000006f", // o
        ]
        .into_iter()
        .map(Felt::from_str)
        .collect();
        starknet_core::types::Event {
            // I think it's a pedersen hash in actuallity, but for the tests I think it's ok
            from_address: starknet_keccak("some_contract_address".as_bytes()),
            keys: vec![
                starknet_keccak("ContractCall".as_bytes()),
                // destination chain
                Felt::from_str(
                    "0x00000000000000000000000000000064657374696e6174696f6e5f636861696e",
                )
                .unwrap(),
            ],
            data: event_data.unwrap(),
        }
    }
}
