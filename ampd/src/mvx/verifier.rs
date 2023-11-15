use crate::handlers::mvx_verify_msg::Message;
use crate::types::Hash;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use multiversx_sdk::data::address::Address;
use multiversx_sdk::data::transaction::{Events, TransactionOnNetwork};

const CONTRACT_CALL_IDENTIFIER: &str = "callContract";
const CONTRACT_CALL_EVENT: &str = "contract_call_event";

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

        let data = unwrap_or_false!(self.data.as_ref());
        let data = unwrap_err_or_false!(STANDARD.decode(data));
        if data.len() < 32 || Hash::from_slice(&data[0..32]) != msg.payload_hash {
            return false;
        }

        return true;
    }
}

fn find_event<'a>(
    transaction: &'a TransactionOnNetwork,
    gateway_address: &Address,
    log_index: usize,
) -> Option<&'a Events> {
    if transaction.logs.is_none() {
        return None;
    }

    let event = transaction.logs.as_ref().unwrap().events.get(log_index);

    if event.is_none() {
        return None;
    }

    let event: &Events = event.unwrap();

    if event.address.to_bytes() != gateway_address.to_bytes() {
        return None;
    }

    if event.identifier != CONTRACT_CALL_IDENTIFIER {
        return None;
    }

    Some(event)
}

pub fn verify_message(
    gateway_address: &Address,
    transaction: &TransactionOnNetwork,
    message: &Message,
) -> bool {
    match find_event(transaction, gateway_address, message.event_index) {
        Some(event) => transaction.hash.as_ref().unwrap() == &message.tx_id && event == message,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use ethers::abi::AbiEncode;
    use multiversx_sdk::data::address::Address;
    use multiversx_sdk::data::transaction::{ApiLogs, Events, TransactionOnNetwork};

    use crate::handlers::mvx_verify_msg::Message;
    use crate::mvx::verifier::{verify_message, CONTRACT_CALL_EVENT};
    use crate::types::{EVMAddress, Hash};
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    #[test]
    fn should_not_verify_msg_if_tx_id_does_not_match() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.tx_id = "someotherid".into();
        assert!(!verify_message(&gateway_address, &tx, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_no_logs() {
        let (gateway_address, mut tx, msg) = get_matching_msg_and_tx();

        tx.logs = None;
        assert!(!verify_message(&gateway_address, &tx, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_event_index_does_not_match() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.event_index = 1;
        assert!(!verify_message(&gateway_address, &tx, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_not_from_gateway() {
        let (gateway_address, mut tx, msg) = get_matching_msg_and_tx();

        let events = &mut tx.logs.as_mut().unwrap().events;
        let event = events.get_mut(0).unwrap();
        event.address = Address::from_bech32_string(
            "erd1qqqqqqqqqqqqqpgqzqvm5ywqqf524efwrhr039tjs29w0qltkklsa05pk7",
        )
        .unwrap();
        assert!(!verify_message(&gateway_address, &tx, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_not_call_contract_identifier() {
        let (gateway_address, mut tx, msg) = get_matching_msg_and_tx();

        let events = &mut tx.logs.as_mut().unwrap().events;
        let event = events.get_mut(0).unwrap();
        event.identifier = "execute".into();
        assert!(!verify_message(&gateway_address, &tx, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_not_call_contract_event() {
        let (gateway_address, mut tx, msg) = get_matching_msg_and_tx();

        let events = &mut tx.logs.as_mut().unwrap().events;
        let event = events.get_mut(0).unwrap();

        let topics = event.topics.as_mut().unwrap();
        let topic = topics.get_mut(0).unwrap();
        *topic = "otherEvent".into();
        assert!(!verify_message(&gateway_address, &tx, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_source_address_does_not_match() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.source_address = Address::from_bech32_string(
            "erd1qqqqqqqqqqqqqpgqsvzyz88e8v8j6x3wquatxuztnxjwnw92kkls6rdtzx",
        )
        .unwrap();
        assert!(!verify_message(&gateway_address, &tx, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_destination_chain_does_not_match() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.destination_chain = "otherchain".parse().unwrap();
        assert!(!verify_message(&gateway_address, &tx, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_destination_address_does_not_match() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.destination_address = EVMAddress::random().to_string();
        assert!(!verify_message(&gateway_address, &tx, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_payload_hash_does_not_match() {
        let (gateway_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.payload_hash = Hash::random();
        assert!(!verify_message(&gateway_address, &tx, &msg));
    }

    #[test]
    fn should_verify_msg_if_correct() {
        let (gateway_address, tx, msg) = get_matching_msg_and_tx();
        assert!(verify_message(&gateway_address, &tx, &msg));
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
            event_index: 0,
            source_address,
            destination_chain: "ethereum".parse().unwrap(),
            destination_address: format!("0x{:x}", EVMAddress::random()).parse().unwrap(),
            payload_hash: Hash::random(),
        };

        // Only the first 32 bytes matter for data
        let mut data = msg.payload_hash.encode();
        data.append(&mut EVMAddress::random().encode());

        // On MultiversX, topics and data are base64 encoded
        let event = Events {
            address: gateway_address.clone(),
            identifier: "callContract".into(),
            topics: Some(vec![
                STANDARD.encode(CONTRACT_CALL_EVENT),
                STANDARD.encode(msg.source_address.clone().to_bytes()),
                STANDARD.encode(msg.destination_chain.to_string()),
                STANDARD.encode(msg.destination_address.clone()),
            ]),
            data: Some(STANDARD.encode(data).into()),
        };

        let other_address = Address::from_bech32_string(
            "erd1qqqqqqqqqqqqqpgqzqvm5ywqqf524efwrhr039tjs29w0qltkklsa05pk7",
        )
        .unwrap();
        let tx_block = TransactionOnNetwork {
            hash: Some(msg.tx_id.clone()),
            logs: Some(ApiLogs {
                address: other_address.clone(),
                events: vec![event],
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
            notarized_at_source_in_meta_nonce: 0,
            notarized_at_source_in_meta_hash: "".into(),
            notarized_at_destination_in_meta_nonce: 0,
            notarized_at_destination_in_meta_hash: "".into(),
            miniblock_type: "".into(),
            miniblock_hash: "".into(),
            timestamp: 1,
            data: None,
            hyperblock_nonce: 1,
            hyperblock_hash: "".into(),
            smart_contract_results: None,
        };

        (gateway_address, tx_block, msg)
    }
}
