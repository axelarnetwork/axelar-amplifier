use crate::handlers::mvx_verify_msg::Message;
use crate::types::Hash;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use multiversx_sdk::data::address::Address;
use multiversx_sdk::data::transaction::{Events, TransactionOnNetwork};

const CONTRACT_CALL_IDENTIFIER: &str = "callContract";
const CONTRACT_CALL_EVENT: &str = "contract_call_event";

impl PartialEq<&Message> for &Events {
    fn eq(&self, msg: &&Message) -> bool {
        if self.identifier != CONTRACT_CALL_IDENTIFIER {
            return false;
        }

        if self.topics.is_none() || self.data.is_none() {
            return false;
        }

        let topics = self.topics.as_ref().unwrap();
        let data = self.data.as_ref().unwrap();

        let event_name = topics.get(0);
        if event_name.is_none() {
            return false;
        }

        let event_name = STANDARD.decode(event_name.unwrap()).unwrap();
        if event_name.as_slice() != CONTRACT_CALL_EVENT.as_bytes() {
            return false;
        }

        let sender = topics.get(1);
        if sender.is_none() {
            return false;
        }

        let sender = STANDARD.decode(sender.unwrap()).unwrap();
        if &sender[0..32] != &msg.source_address.to_bytes() {
            return false;
        }

        let destination_chain = topics.get(2);
        if destination_chain.is_none() {
            return false;
        }

        let destination_chain = STANDARD.decode(destination_chain.unwrap()).unwrap();
        if String::from_utf8(destination_chain).unwrap() != msg.destination_chain.to_string() {
            return false;
        }

        let destination_address = topics.get(3);
        if destination_address.is_none() {
            return false;
        }

        let destination_address = STANDARD.decode(destination_address.unwrap()).unwrap();
        if String::from_utf8(destination_address).unwrap() != msg.destination_address {
            return false;
        }

        let data = STANDARD.decode(data).unwrap();
        if Hash::from_slice(&data[0..32]) != msg.payload_hash {
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
