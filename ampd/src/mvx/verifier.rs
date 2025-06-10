use axelar_wasm_std::voting::Vote;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hex::ToHex;
use multiversx_sdk::data::address::Address;
use multiversx_sdk::data::transaction::{Events, TransactionOnNetwork};
use num_traits::cast;
use router_api::ChainName;
use tracing::debug;

use crate::handlers::mvx_verify_msg::Message;
use crate::handlers::mvx_verify_verifier_set::VerifierSetConfirmation;
use crate::mvx::error::Error;
use crate::mvx::WeightedSigners;
use crate::types::Hash;

const CONTRACT_CALL_IDENTIFIER: &str = "callContract";
const CONTRACT_CALL_EVENT: &str = "contract_call_event";

const ROTATE_SIGNERS_IDENTIFIER: &str = "rotateSigners";
const SIGNERS_ROTATED_EVENT: &str = "signers_rotated_event";

impl Message {
    fn eq_event(&self, event: &Events) -> Result<bool, Box<dyn std::error::Error>> {
        if event.identifier != CONTRACT_CALL_IDENTIFIER {
            return Ok(false);
        }

        let topics = event.topics.as_ref().ok_or(Error::PropertyEmpty)?;

        let event_name = topics.first().ok_or(Error::PropertyEmpty)?;
        let event_name = STANDARD.decode(event_name)?;
        if event_name.as_slice() != CONTRACT_CALL_EVENT.as_bytes() {
            return Ok(false);
        }

        let sender = topics.get(1).ok_or(Error::PropertyEmpty)?;
        let sender = STANDARD.decode(sender)?;
        if sender.len() != 32 || sender[0..32] != self.source_address.to_bytes() {
            return Ok(false);
        }

        let destination_chain = topics.get(2).ok_or(Error::PropertyEmpty)?;
        let destination_chain = STANDARD.decode(destination_chain)?;
        let destination_chain = String::from_utf8(destination_chain)?;
        let destination_chain = ChainName::try_from(destination_chain)
            .inspect_err(|e| debug!(error = ?e, "failed to parse destination chain"))?;
        if destination_chain != self.destination_chain.as_ref() {
            return Ok(false);
        }

        let destination_address = topics.get(3).ok_or(Error::PropertyEmpty)?;
        let destination_address = STANDARD.decode(destination_address)?;
        let destination_address = String::from_utf8(destination_address)?;
        if destination_address != self.destination_address {
            return Ok(false);
        }

        let payload_hash = topics.get(4).ok_or(Error::PropertyEmpty)?;
        let payload_hash = STANDARD.decode(payload_hash)?;
        if payload_hash.len() != 32
            || Hash::from_slice(payload_hash.as_slice()) != self.payload_hash
        {
            return Ok(false);
        }

        Ok(true)
    }
}

impl VerifierSetConfirmation {
    fn eq_event(&self, event: &Events) -> Result<bool, Box<dyn std::error::Error>> {
        if event.identifier != ROTATE_SIGNERS_IDENTIFIER {
            return Ok(false);
        }

        let topics = event.topics.as_ref().ok_or(Error::PropertyEmpty)?;

        let event_name = topics.first().ok_or(Error::PropertyEmpty)?;
        let event_name = STANDARD.decode(event_name)?;
        if event_name.as_slice() != SIGNERS_ROTATED_EVENT.as_bytes() {
            return Ok(false);
        }

        let signers_hash = topics.get(2).ok_or(Error::PropertyEmpty)?;
        let signers_hash = STANDARD.decode(signers_hash)?;

        let weighted_signers = WeightedSigners::from(&self.verifier_set);
        if signers_hash.len() != 32 || signers_hash.as_slice() != weighted_signers.hash().as_slice()
        {
            return Ok(false);
        }

        Ok(true)
    }
}

fn find_event<'a>(
    transaction: &'a TransactionOnNetwork,
    gateway_address: &Address,
    log_index: u64,
) -> Option<&'a Events> {
    let log_index: usize = cast(log_index).expect("log_index must be a valid usize");

    let event = transaction.logs.as_ref()?.events.get(log_index)?;

    if event.address.to_bytes() != gateway_address.to_bytes() {
        return None;
    }

    Some(event)
}

pub fn verify_message(
    gateway_address: &Address,
    transaction: &TransactionOnNetwork,
    message: &Message,
) -> Vote {
    let hash = transaction.hash.as_deref().unwrap_or_default();

    if hash.is_empty() {
        return Vote::NotFound;
    }

    match find_event(transaction, gateway_address, message.message_id.event_index) {
        Some(event)
            if hash == message.message_id.tx_hash.encode_hex::<String>().as_str()
                && message.eq_event(event).unwrap_or(false) =>
        {
            Vote::SucceededOnChain
        }
        _ => Vote::NotFound,
    }
}

pub fn verify_verifier_set(
    gateway_address: &Address,
    transaction: &TransactionOnNetwork,
    verifier_set: VerifierSetConfirmation,
) -> Vote {
    let hash = transaction.hash.as_deref().unwrap_or_default();

    if hash.is_empty() {
        return Vote::NotFound;
    }

    match find_event(
        transaction,
        gateway_address,
        verifier_set.message_id.event_index,
    ) {
        Some(event)
            if hash
                == verifier_set
                    .message_id
                    .tx_hash
                    .encode_hex::<String>()
                    .as_str()
                && verifier_set.eq_event(event).unwrap_or(false) =>
        {
            Vote::SucceededOnChain
        }
        _ => Vote::NotFound,
    }
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelar_wasm_std::voting::Vote;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use cosmwasm_std::{HexBinary, Uint128};
    use hex::ToHex;
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ed25519_test_data};
    use multiversx_sdk::data::address::Address;
    use multiversx_sdk::data::transaction::{ApiLogs, Events, LogData, TransactionOnNetwork};

    use crate::handlers::mvx_verify_msg::Message;
    use crate::handlers::mvx_verify_verifier_set::VerifierSetConfirmation;
    use crate::mvx::verifier::{
        verify_message, verify_verifier_set, CONTRACT_CALL_EVENT, CONTRACT_CALL_IDENTIFIER,
        ROTATE_SIGNERS_IDENTIFIER, SIGNERS_ROTATED_EVENT,
    };
    use crate::types::{EVMAddress, Hash};

    // test verify message
    #[test]
    fn should_not_verify_msg_if_tx_id_does_not_match() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.message_id.tx_hash = Hash::random().into();
        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[test]
    fn should_not_verify_msg_if_no_logs() {
        let (gateway_address, mut tx, msg) = get_matching_msg_and_tx();

        tx.logs = None;
        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[test]
    fn should_not_verify_msg_if_no_log_for_event_index() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.message_id.event_index = 2;
        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[test]
    fn should_not_verify_msg_if_event_index_does_not_match() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.message_id.event_index = 0;
        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[test]
    fn should_not_verify_msg_if_not_from_gateway() {
        let (gateway_address, mut tx, msg) = get_matching_msg_and_tx();

        let events = &mut tx.logs.as_mut().unwrap().events;
        let event = events.get_mut(1).unwrap();
        event.address = Address::from_bech32_string(
            "erd1qqqqqqqqqqqqqpgqzqvm5ywqqf524efwrhr039tjs29w0qltkklsa05pk7",
        )
        .unwrap();
        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[test]
    fn should_not_verify_msg_if_not_call_contract_identifier() {
        let (gateway_address, mut tx, msg) = get_matching_msg_and_tx();

        let events = &mut tx.logs.as_mut().unwrap().events;
        let event = events.get_mut(1).unwrap();
        event.identifier = "other".into();
        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[test]
    fn should_not_verify_msg_if_not_call_contract_event() {
        let (gateway_address, mut tx, msg) = get_matching_msg_and_tx();

        let events = &mut tx.logs.as_mut().unwrap().events;
        let event = events.get_mut(1).unwrap();

        let topics = event.topics.as_mut().unwrap();
        let topic = topics.get_mut(0).unwrap();
        *topic = "other".into();
        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[test]
    fn should_not_verify_msg_if_source_address_does_not_match() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.source_address = Address::from_bech32_string(
            "erd1qqqqqqqqqqqqqpgqsvzyz88e8v8j6x3wquatxuztnxjwnw92kkls6rdtzx",
        )
        .unwrap();
        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[test]
    fn should_not_verify_msg_if_destination_chain_does_not_match() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.destination_chain = "otherchain".parse().unwrap();
        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[test]
    fn should_not_verify_msg_if_destination_address_does_not_match() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.destination_address = EVMAddress::random().to_string();
        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[test]
    fn should_not_verify_msg_if_payload_hash_does_not_match() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.payload_hash = Hash::random();
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

    #[test]
    fn should_verify_msg_if_chain_uses_different_casing() {
        let (gateway_address, tx, msg) = msg_and_tx_on_network_with_different_chain_casing();

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
    fn should_not_verify_verifier_set_if_no_logs() {
        let (gateway_address, mut tx, verifier_set) = get_matching_verifier_set_and_tx();

        tx.logs = None;
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

        let events = &mut tx.logs.as_mut().unwrap().events;
        let event = events.get_mut(1).unwrap();
        event.address = Address::from_bech32_string(
            "erd1qqqqqqqqqqqqqpgqzqvm5ywqqf524efwrhr039tjs29w0qltkklsa05pk7",
        )
        .unwrap();
        assert_eq!(
            verify_verifier_set(&gateway_address, &tx, verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_not_rotate_signers_identifier() {
        let (gateway_address, mut tx, verifier_set) = get_matching_verifier_set_and_tx();

        let events = &mut tx.logs.as_mut().unwrap().events;
        let event = events.get_mut(1).unwrap();
        event.identifier = "callContract".into();
        assert_eq!(
            verify_verifier_set(&gateway_address, &tx, verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_not_signers_rotated_event() {
        let (gateway_address, mut tx, verifier_set) = get_matching_verifier_set_and_tx();

        let events = &mut tx.logs.as_mut().unwrap().events;
        let event = events.get_mut(1).unwrap();

        let topics = event.topics.as_mut().unwrap();
        let topic = topics.get_mut(0).unwrap();
        *topic = "otherEvent".into();
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
    fn should_verify_verifier() {
        let (gateway_address, tx, verifier_set) = get_matching_verifier_set_and_tx();

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx, verifier_set),
            Vote::SucceededOnChain
        );
    }

    fn mock_message(destination_chain: &str) -> Message {
        let source_address = Address::from_bech32_string(
            "erd1qqqqqqqqqqqqqpgqzqvm5ywqqf524efwrhr039tjs29w0qltkklsa05pk7",
        )
        .unwrap();

        let message_id = HexTxHashAndEventIndex::new(Hash::random(), 1u64);

        Message {
            message_id,
            source_address,
            destination_chain: destination_chain.parse().unwrap(),
            destination_address: format!("0x{:x}", EVMAddress::random()).parse().unwrap(),
            payload_hash: Hash::random(),
        }
    }

    fn mock_tx_on_network(
        destination_chain: &str,
        gateway_address: &Address,
        msg: &Message,
    ) -> TransactionOnNetwork {
        let payload_hash = msg.payload_hash;

        let wrong_event = Events {
            address: gateway_address.clone(),
            identifier: CONTRACT_CALL_IDENTIFIER.into(),
            topics: Some(vec![STANDARD.encode(SIGNERS_ROTATED_EVENT)]), // wrong event name
            data: LogData::Empty,
        };

        // On MultiversX, topics and data are base64 encoded
        let event = Events {
            address: gateway_address.clone(),
            identifier: CONTRACT_CALL_IDENTIFIER.into(),
            topics: Some(vec![
                STANDARD.encode(CONTRACT_CALL_EVENT),
                STANDARD.encode(msg.source_address.clone().to_bytes()),
                STANDARD.encode(destination_chain),
                STANDARD.encode(msg.destination_address.clone()),
                STANDARD.encode(payload_hash),
            ]),
            data: LogData::String("".into()), // data is irrelevant here since it contains only the offchain payload
        };

        let other_address = Address::from_bech32_string(
            "erd1qqqqqqqqqqqqqpgqzqvm5ywqqf524efwrhr039tjs29w0qltkklsa05pk7",
        )
        .unwrap();

        TransactionOnNetwork {
            hash: Some(msg.message_id.tx_hash.encode_hex::<String>()),
            logs: Some(ApiLogs {
                address: other_address.clone(),
                events: vec![wrong_event, event],
            }),
            status: "success".into(),
            // The rest are irrelevant but there is no default
            kind: "".into(),
            nonce: 1,
            round: 1,
            epoch: 1,
            value: "".into(),
            receiver: other_address.clone(),
            sender: other_address,
            gas_price: 0,
            gas_limit: 0,
            signature: "".into(),
            source_shard: 1,
            destination_shard: 1,
            block_nonce: 1,
            block_hash: "".into(),
            notarized_at_source_in_meta_nonce: Some(0),
            notarized_at_source_in_meta_hash: Some("".into()),
            notarized_at_destination_in_meta_nonce: Some(0),
            notarized_at_destination_in_meta_hash: Some("".into()),
            miniblock_type: "".into(),
            miniblock_hash: "".into(),
            timestamp: 1,
            data: None,
            hyperblock_nonce: Some(1),
            hyperblock_hash: Some("".into()),
            smart_contract_results: vec![],
            processing_type_on_destination: "".into(),
        }
    }

    fn get_matching_msg_and_tx() -> (Address, TransactionOnNetwork, Message) {
        let gateway_address = Address::from_bech32_string(
            "erd1qqqqqqqqqqqqqpgqsvzyz88e8v8j6x3wquatxuztnxjwnw92kkls6rdtzx",
        )
        .unwrap();

        let destination_chain = "ethereum";
        let msg = mock_message(destination_chain);
        let tx_block = mock_tx_on_network(destination_chain, &gateway_address, &msg);

        (gateway_address, tx_block, msg)
    }

    fn msg_and_tx_on_network_with_different_chain_casing(
    ) -> (Address, TransactionOnNetwork, Message) {
        let gateway_address = Address::from_bech32_string(
            "erd1qqqqqqqqqqqqqpgqsvzyz88e8v8j6x3wquatxuztnxjwnw92kkls6rdtzx",
        )
        .unwrap();

        let msg = mock_message("ethereum");
        let tx_block = mock_tx_on_network("Ethereum", &gateway_address, &msg);

        (gateway_address, tx_block, msg)
    }

    fn get_matching_verifier_set_and_tx() -> (Address, TransactionOnNetwork, VerifierSetConfirmation)
    {
        let gateway_address = Address::from_bech32_string(
            "erd1qqqqqqqqqqqqqpgqsvzyz88e8v8j6x3wquatxuztnxjwnw92kkls6rdtzx",
        )
        .unwrap();
        let message_id = HexTxHashAndEventIndex::new(Hash::random(), 1u64);

        let mut signers = ed25519_test_data::signers();
        signers.sort_by_key(|signer| signer.address.clone());
        let mut verifier_set_confirmation = VerifierSetConfirmation {
            message_id,
            verifier_set: build_verifier_set(KeyType::Ed25519, &signers),
        };
        verifier_set_confirmation.verifier_set.created_at = 5;

        // 00000003 - length of new signers
        // signers.0.pub_key - first new signer
        // 00000001 01 - length of biguint weight followed by 1 as hex
        // signers.1.pub_key - second new signer
        // 00000001 01 - length of biguint weight followed by 1 as hex
        // signers.2.pub_key - third new signer
        // 00000001 01 - length of biguint weight followed by 1 as hex
        // 00000001 02 - length of biguint threshold followed by 2 as hex
        // 0000000000000000000000000000000000000000000000000000000000000005 - the nonce (created_at date as uint256)
        let data = HexBinary::from_hex(&format!("00000003{}0000000101{}0000000101{}000000010100000001020000000000000000000000000000000000000000000000000000000000000005", signers.first().unwrap().pub_key.to_hex(),signers.get(1).unwrap().pub_key.to_hex(),signers.get(2).unwrap().pub_key.to_hex()))
            .unwrap();
        // This hash is generated externally using the MultiversX Gateway contract and is 100% correct
        let signers_hash =
            HexBinary::from_hex("0428071d4f8abb85c164854b7a29ff1fefccb0c392b0200ee1e2bc8784abaa3a")
                .unwrap();

        let wrong_event = Events {
            address: gateway_address.clone(),
            identifier: ROTATE_SIGNERS_IDENTIFIER.into(),
            topics: Some(vec![STANDARD.encode(CONTRACT_CALL_EVENT)]), // wrong event name
            data: LogData::Empty,
        };

        // On MultiversX, topics and data are base64 encoded
        let event = Events {
            address: gateway_address.clone(),
            identifier: ROTATE_SIGNERS_IDENTIFIER.into(),
            topics: Some(vec![
                STANDARD.encode(SIGNERS_ROTATED_EVENT),
                STANDARD.encode("0"),          // epoch (irrelevant here)
                STANDARD.encode(signers_hash), // signers hash
            ]),
            data: LogData::String(STANDARD.encode(data)),
        };

        let other_address = Address::from_bech32_string(
            "erd1qqqqqqqqqqqqqpgqzqvm5ywqqf524efwrhr039tjs29w0qltkklsa05pk7",
        )
        .unwrap();
        let tx_block = TransactionOnNetwork {
            hash: Some(
                verifier_set_confirmation
                    .message_id
                    .tx_hash
                    .encode_hex::<String>(),
            ),
            logs: Some(ApiLogs {
                address: other_address.clone(),
                events: vec![wrong_event, event],
            }),
            status: "success".into(),
            // The rest are irrelevant but there is no default
            kind: "".into(),
            nonce: 1,
            round: 1,
            epoch: 1,
            value: "".into(),
            receiver: other_address.clone(),
            sender: other_address,
            gas_price: 0,
            gas_limit: 0,
            signature: "".into(),
            source_shard: 1,
            destination_shard: 1,
            block_nonce: 1,
            block_hash: "".into(),
            notarized_at_source_in_meta_nonce: Some(0),
            notarized_at_source_in_meta_hash: Some("".into()),
            notarized_at_destination_in_meta_nonce: Some(0),
            notarized_at_destination_in_meta_hash: Some("".into()),
            miniblock_type: "".into(),
            miniblock_hash: "".into(),
            timestamp: 1,
            data: None,
            hyperblock_nonce: Some(1),
            hyperblock_hash: Some("".into()),
            smart_contract_results: vec![],
            processing_type_on_destination: "".into(),
        };

        (gateway_address, tx_block, verifier_set_confirmation)
    }
}
