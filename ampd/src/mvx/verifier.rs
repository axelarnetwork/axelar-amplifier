use crate::handlers::mvx_verify_msg::Message;
use crate::handlers::mvx_verify_verifier_set::VerifierSetConfirmation;
use crate::types::Hash;
use axelar_wasm_std::voting::Vote;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use multisig_prover::encoding::mvx::WeightedSigners;
use multiversx_sdk::data::address::Address;
use multiversx_sdk::data::transaction::{Events, TransactionOnNetwork};

const CONTRACT_CALL_IDENTIFIER: &str = "callContract";
const CONTRACT_CALL_EVENT: &str = "contract_call_event";

const ROTATE_SIGNERS_IDENTIFIER: &str = "rotateSigners";
const SIGNERS_ROTATED_EVENT: &str = "signers_rotated_event";

macro_rules! unwrap_or_continue {
    ( $data:expr ) => {
        match $data {
            Some(x) => x,
            None => continue,
        }
    };
}

macro_rules! unwrap_or_false {
    ( $data:expr ) => {
        match $data {
            Some(x) => x,
            None => return false,
        }
    };
}

macro_rules! unwrap_err_or_false {
    ( $err:expr ) => {
        match $err {
            Ok(x) => x,
            Err(_) => return false,
        }
    };
}

impl PartialEq<&Message> for &Events {
    fn eq(&self, msg: &&Message) -> bool {
        if self.identifier != CONTRACT_CALL_IDENTIFIER {
            return false;
        }

        let topics = unwrap_or_false!(self.topics.as_ref());

        let event_name = unwrap_or_false!(topics.get(0));
        let event_name = unwrap_err_or_false!(STANDARD.decode(event_name));
        if event_name.as_slice() != CONTRACT_CALL_EVENT.as_bytes() {
            return false;
        }

        let sender = unwrap_or_false!(topics.get(1));
        let sender = unwrap_err_or_false!(STANDARD.decode(sender));
        if sender.len() != 32 || &sender[0..32] != &msg.source_address.to_bytes() {
            return false;
        }

        let destination_chain = unwrap_or_false!(topics.get(2));
        let destination_chain = unwrap_err_or_false!(STANDARD.decode(destination_chain));
        let destination_chain = unwrap_err_or_false!(String::from_utf8(destination_chain));
        if destination_chain != msg.destination_chain.to_string() {
            return false;
        }

        let destination_address = unwrap_or_false!(topics.get(3));
        let destination_address = unwrap_err_or_false!(STANDARD.decode(destination_address));
        let destination_address = unwrap_err_or_false!(String::from_utf8(destination_address));
        if destination_address != msg.destination_address {
            return false;
        }

        let payload_hash = unwrap_or_false!(topics.get(4));
        let payload_hash = unwrap_err_or_false!(STANDARD.decode(payload_hash));
        if payload_hash.len() != 32 || Hash::from_slice(payload_hash.as_slice()) != msg.payload_hash
        {
            return false;
        }

        return true;
    }
}

impl PartialEq<VerifierSetConfirmation> for &Events {
    fn eq(&self, verifier_set: &VerifierSetConfirmation) -> bool {
        if self.identifier != ROTATE_SIGNERS_IDENTIFIER {
            return false;
        }

        let topics = unwrap_or_false!(self.topics.as_ref());

        let event_name = unwrap_or_false!(topics.get(0));
        let event_name = unwrap_err_or_false!(STANDARD.decode(event_name));
        if event_name.as_slice() != SIGNERS_ROTATED_EVENT.as_bytes() {
            return false;
        }

        let signers_hash = unwrap_or_false!(topics.get(2));
        let signers_hash = unwrap_err_or_false!(STANDARD.decode(signers_hash));

        let data = unwrap_or_false!(self.data.as_ref());
        let data = unwrap_err_or_false!(STANDARD.decode(data));

        let weighted_signers = WeightedSigners::from(&verifier_set.verifier_set);

        if signers_hash.len() != 32 || signers_hash.as_slice() != weighted_signers.hash().as_slice()
        {
            return false;
        }

        let encoded = unwrap_err_or_false!(weighted_signers.encode());
        if encoded != data {
            return false;
        }

        return true;
    }
}

fn find_event<'a>(
    transaction: &'a TransactionOnNetwork,
    gateway_address: &Address,
    log_index: usize,
    identifier: &str,
    needed_event_name: &[u8],
) -> Option<&'a Events> {
    if transaction.logs.is_none() {
        return None;
    }

    // Because of current relayer limitation, if log_index is 0, we will search through the logs and get the first log
    // which corresponds to the gateway address, hence only supporting one cross chain call per transaction
    if log_index == 0 {
        for event in transaction.logs.as_ref().unwrap().events.iter() {
            if event.address.to_bytes() == gateway_address.to_bytes()
                && event.identifier == identifier
            {
                let topics = unwrap_or_continue!(event.topics.as_ref());

                let event_name = unwrap_or_continue!(topics.get(0));
                let event_name = STANDARD.decode(event_name).unwrap_or(Vec::new());
                if event_name.as_slice() == needed_event_name {
                    return Some(event);
                }
            }
        }

        return None;
    }

    // Support normal log_index for the future when relayer can be properly implemented
    let event = transaction.logs.as_ref().unwrap().events.get(log_index);

    if event.is_none() {
        return None;
    }

    let event: &Events = event.unwrap();

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
    match find_event(
        transaction,
        gateway_address,
        message.event_index as usize,
        CONTRACT_CALL_IDENTIFIER,
        CONTRACT_CALL_EVENT.as_bytes(),
    ) {
        Some(event) if transaction.hash.as_ref().unwrap() == &message.tx_id && event == message => {
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
    match find_event(
        transaction,
        gateway_address,
        verifier_set.event_index as usize,
        ROTATE_SIGNERS_IDENTIFIER,
        SIGNERS_ROTATED_EVENT.as_bytes(),
    ) {
        Some(event)
            if transaction.hash.as_ref().unwrap() == &verifier_set.tx_id
                && event == verifier_set =>
        {
            Vote::SucceededOnChain
        }
        _ => Vote::NotFound,
    }
}

#[cfg(test)]
mod tests {
    use ethers::abi::AbiEncode;
    use multiversx_sdk::data::address::Address;
    use multiversx_sdk::data::transaction::{ApiLogs, Events, TransactionOnNetwork};

    use crate::handlers::mvx_verify_msg::Message;
    use crate::mvx::verifier::{verify_message, CONTRACT_CALL_EVENT, CONTRACT_CALL_IDENTIFIER, SIGNERS_ROTATED_EVENT, verify_verifier_set, ROTATE_SIGNERS_IDENTIFIER};
    use crate::types::{EVMAddress, Hash};
    use axelar_wasm_std::voting::Vote;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use cosmwasm_std::{HexBinary, Uint128};
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ed25519_test_data};
    use crate::handlers::mvx_verify_verifier_set::VerifierSetConfirmation;

    // test verify message
    #[test]
    fn should_not_verify_msg_if_tx_id_does_not_match() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.tx_id = "someotherid".into();
        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[test]
    fn should_not_verify_msg_if_no_logs() {
        let (gateway_address, mut tx, msg) = get_matching_msg_and_tx();

        tx.logs = None;
        assert_eq!(verify_message(&gateway_address, &tx, &msg), Vote::NotFound);
    }

    #[test]
    fn should_not_verify_msg_if_event_index_does_not_match() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.event_index = 2;
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
    fn should_verify_msg_if_correct() {
        let (gateway_address, tx, msg) = get_matching_msg_and_tx();
        assert_eq!(
            verify_message(&gateway_address, &tx, &msg),
            Vote::SucceededOnChain
        );
    }

    #[test]
    fn should_verify_msg_if_correct_event_index_0() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.event_index = 0;
        assert_eq!(
            verify_message(&gateway_address, &tx, &msg),
            Vote::SucceededOnChain
        );
    }

    // test verify worker set
    #[test]
    fn should_not_verify_verifier_set_if_tx_id_does_not_match() {
        let (gateway_address, tx, mut verifier_set) = get_matching_verifier_set_and_tx();

        verifier_set.tx_id = "someotherid".into();
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
    fn should_not_verify_verifier_set_if_event_index_does_not_match() {
        let (gateway_address, tx, mut verifier_set) = get_matching_verifier_set_and_tx();

        verifier_set.event_index = 2;
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
    fn should_verify_verifier_set_if_correct() {
        let (gateway_address, tx, verifier_set) = get_matching_verifier_set_and_tx();
        assert_eq!(
            verify_verifier_set(&gateway_address, &tx, verifier_set),
            Vote::SucceededOnChain
        );
    }

    #[test]
    fn should_verify_verifier_set_if_correct_event_index_0() {
        let (gateway_address, tx, mut verifier_set) = get_matching_verifier_set_and_tx();

        verifier_set.event_index = 0;
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
        let tx_id = "dfaf64de66510723f2efbacd7ead3c4f8c856aed1afc2cb30254552aeda47312";

        let msg = Message {
            tx_id: tx_id.to_string(),
            event_index: 1,
            source_address,
            destination_chain: "ethereum".parse().unwrap(),
            destination_address: format!("0x{:x}", EVMAddress::random()).parse().unwrap(),
            payload_hash: Hash::random(),
        };

        // Only the first 32 bytes matter for data
        let payload_hash = msg.payload_hash.encode();

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
            hash: Some(msg.tx_id.clone()),
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

    fn get_matching_verifier_set_and_tx() -> (Address, TransactionOnNetwork, VerifierSetConfirmation) {
        let gateway_address = Address::from_bech32_string(
            "erd1qqqqqqqqqqqqqpgqsvzyz88e8v8j6x3wquatxuztnxjwnw92kkls6rdtzx",
        )
        .unwrap();
        let tx_id = "dfaf64de66510723f2efbacd7ead3c4f8c856aed1afc2cb30254552aeda47312";

        let verifier_set_confirmation = VerifierSetConfirmation {
            tx_id: tx_id.to_string(),
            event_index: 1,
            verifier_set: build_verifier_set(KeyType::Ed25519, &ed25519_test_data::signers()),
        };

        // 00000003 - length of new signers
        // 45e67eaf446e6c26eb3a2b55b64339ecf3a4d1d03180bee20eb5afdd23fa644f - first new signer
        // 00000001 01 - length of biguint weight followed by 1 as hex
        // c387253d29085a8036d6ae2cafb1b14699751417c0ce302cfe03da279e6b5c04 - second new signer
        // 00000001 01 - length of biguint weight followed by 1 as hex
        // dd9822c7fa239dda9913ebee813ecbe69e35d88ff651548d5cc42c033a8a667b - third new signer
        // 00000001 01 - length of biguint weight followed by 1 as hex
        // 00000001 02 - length of biguint threshold followed by 2 as hex
        // 290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563 - the nonce (keccak256 hash of Uin256 number 0, created_at date)
        let data = HexBinary::from_hex("0000000345e67eaf446e6c26eb3a2b55b64339ecf3a4d1d03180bee20eb5afdd23fa644f0000000101c387253d29085a8036d6ae2cafb1b14699751417c0ce302cfe03da279e6b5c040000000101dd9822c7fa239dda9913ebee813ecbe69e35d88ff651548d5cc42c033a8a667b00000001010000000102290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563")
            .unwrap();
        let signers_hash = HexBinary::from_hex("acc61d8597eaf76375dd9e34c50baab3c110d508ed4bd99c8d6000af503bf770").unwrap();

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
                STANDARD.encode("0"), // epoch (irrelevant here)
                STANDARD.encode(signers_hash), // signers hash
            ]),
            data: Some(STANDARD.encode(data).into()),
        };

        let other_address = Address::from_bech32_string(
            "erd1qqqqqqqqqqqqqpgqzqvm5ywqqf524efwrhr039tjs29w0qltkklsa05pk7",
        )
        .unwrap();
        let tx_block = TransactionOnNetwork {
            hash: Some(tx_id.to_string()),
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
