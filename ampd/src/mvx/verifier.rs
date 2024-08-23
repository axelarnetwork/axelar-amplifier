use axelar_wasm_std::voting::Vote;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hex::ToHex;
use multiversx_sdk::data::address::Address;
use multiversx_sdk::data::transaction::{Events, TransactionOnNetwork};
use num_traits::cast;

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
    log_index: u32,
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

    match find_event(transaction, gateway_address, message.event_index) {
        Some(event)
            if hash == message.tx_id.encode_hex::<String>().as_str()
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

    match find_event(transaction, gateway_address, verifier_set.event_index) {
        Some(event)
            if hash == verifier_set.tx_id.encode_hex::<String>().as_str()
                && verifier_set.eq_event(event).unwrap_or(false) =>
        {
            Vote::SucceededOnChain
        }
        _ => Vote::NotFound,
    }
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::voting::Vote;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use cosmwasm_std::{HexBinary, Uint128};
    use hex::ToHex;
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ed25519_test_data};
    use multiversx_sdk::data::address::Address;
    use multiversx_sdk::data::transaction::{ApiLogs, Events, TransactionOnNetwork};

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

        msg.tx_id = "ffaf64de66510723f2efbacd7ead3c4f8c856aed1afc2cb30254552aeda47313"
            .parse()
            .unwrap();
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

        msg.event_index = 2;
        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[test]
    fn should_not_verify_msg_if_event_index_does_not_match() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.event_index = 0;
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

    // test verify worker set
    #[test]
    fn should_not_verify_verifier_set_if_tx_id_does_not_match() {
        let (gateway_address, tx, mut verifier_set) = get_matching_verifier_set_and_tx();

        verifier_set.tx_id = "ffaf64de66510723f2efbacd7ead3c4f8c856aed1afc2cb30254552aeda47313"
            .parse()
            .unwrap();
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

        verifier_set.event_index = 2;
        assert_eq!(
            verify_verifier_set(&gateway_address, &tx, verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_event_index_does_not_match() {
        let (gateway_address, tx, mut verifier_set) = get_matching_verifier_set_and_tx();

        verifier_set.event_index = 0;
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

    fn get_matching_msg_and_tx() -> (Address, TransactionOnNetwork, Message) {
        let gateway_address = Address::from_bech32_string(
            "erd1qqqqqqqqqqqqqpgqsvzyz88e8v8j6x3wquatxuztnxjwnw92kkls6rdtzx",
        )
        .unwrap();
        let source_address = Address::from_bech32_string(
            "erd1qqqqqqqqqqqqqpgqzqvm5ywqqf524efwrhr039tjs29w0qltkklsa05pk7",
        )
        .unwrap();
        let tx_id = "dfaf64de66510723f2efbacd7ead3c4f8c856aed1afc2cb30254552aeda47312"
            .parse()
            .unwrap();

        let msg = Message {
            tx_id,
            event_index: 1,
            source_address,
            destination_chain: "ethereum".parse().unwrap(),
            destination_address: format!("0x{:x}", EVMAddress::random()).parse().unwrap(),
            payload_hash: Hash::random(),
        };

        // Only the first 32 bytes matter for data
        let payload_hash = msg.payload_hash;

        let wrong_event = Events {
            address: gateway_address.clone(),
            identifier: CONTRACT_CALL_IDENTIFIER.into(),
            topics: Some(vec![STANDARD.encode(SIGNERS_ROTATED_EVENT)]), // wrong event name
            data: None,
        };

        // On MultiversX, topics and data are base64 encoded
        let event = Events {
            address: gateway_address.clone(),
            identifier: CONTRACT_CALL_IDENTIFIER.into(),
            topics: Some(vec![
                STANDARD.encode(CONTRACT_CALL_EVENT),
                STANDARD.encode(msg.source_address.clone().to_bytes()),
                STANDARD.encode(msg.destination_chain.to_string()),
                STANDARD.encode(msg.destination_address.clone()),
                STANDARD.encode(payload_hash),
            ]),
            data: Some("".into()), // data is irrelevant here since it contains only the offchain payload
        };

        let other_address = Address::from_bech32_string(
            "erd1qqqqqqqqqqqqqpgqzqvm5ywqqf524efwrhr039tjs29w0qltkklsa05pk7",
        )
        .unwrap();
        let tx_block = TransactionOnNetwork {
            hash: Some(msg.tx_id.encode_hex::<String>()),
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
            smart_contract_results: None,
            processing_type_on_destination: "".into(),
        };

        (gateway_address, tx_block, msg)
    }

    fn get_matching_verifier_set_and_tx() -> (Address, TransactionOnNetwork, VerifierSetConfirmation)
    {
        let gateway_address = Address::from_bech32_string(
            "erd1qqqqqqqqqqqqqpgqsvzyz88e8v8j6x3wquatxuztnxjwnw92kkls6rdtzx",
        )
        .unwrap();
        let tx_id = "dfaf64de66510723f2efbacd7ead3c4f8c856aed1afc2cb30254552aeda47312"
            .parse()
            .unwrap();

        let mut verifier_set_confirmation = VerifierSetConfirmation {
            tx_id,
            event_index: 1,
            verifier_set: build_verifier_set(KeyType::Ed25519, &ed25519_test_data::signers()),
        };
        verifier_set_confirmation.verifier_set.created_at = 5;

        // 00000003 - length of new signers
        // 45e67eaf446e6c26eb3a2b55b64339ecf3a4d1d03180bee20eb5afdd23fa644f - first new signer
        // 00000001 01 - length of biguint weight followed by 1 as hex
        // c387253d29085a8036d6ae2cafb1b14699751417c0ce302cfe03da279e6b5c04 - second new signer
        // 00000001 01 - length of biguint weight followed by 1 as hex
        // dd9822c7fa239dda9913ebee813ecbe69e35d88ff651548d5cc42c033a8a667b - third new signer
        // 00000001 01 - length of biguint weight followed by 1 as hex
        // 00000001 02 - length of biguint threshold followed by 2 as hex
        // 0000000000000000000000000000000000000000000000000000000000000005 - the nonce (created_at date as uint256)
        let data = HexBinary::from_hex("0000000345e67eaf446e6c26eb3a2b55b64339ecf3a4d1d03180bee20eb5afdd23fa644f0000000101c387253d29085a8036d6ae2cafb1b14699751417c0ce302cfe03da279e6b5c040000000101dd9822c7fa239dda9913ebee813ecbe69e35d88ff651548d5cc42c033a8a667b000000010100000001020000000000000000000000000000000000000000000000000000000000000005")
            .unwrap();
        let signers_hash =
            HexBinary::from_hex("29f81aa379fa1f5973d05dd25e5ae4bc1afa2aa30156b1db5ec437a46ba4fd28")
                .unwrap();

        let wrong_event = Events {
            address: gateway_address.clone(),
            identifier: ROTATE_SIGNERS_IDENTIFIER.into(),
            topics: Some(vec![STANDARD.encode(CONTRACT_CALL_EVENT)]), // wrong event name
            data: None,
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
            data: Some(STANDARD.encode(data)),
        };

        let other_address = Address::from_bech32_string(
            "erd1qqqqqqqqqqqqqpgqzqvm5ywqqf524efwrhr039tjs29w0qltkklsa05pk7",
        )
        .unwrap();
        let tx_block = TransactionOnNetwork {
            hash: Some(tx_id.encode_hex::<String>()),
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
            smart_contract_results: None,
            processing_type_on_destination: "".into(),
        };

        (gateway_address, tx_block, verifier_set_confirmation)
    }
}
