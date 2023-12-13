use bcs::to_bytes;
use move_core_types::language_storage::StructTag;
use serde::Deserialize;
use sui_json_rpc_types::{SuiEvent, SuiTransactionBlockResponse};
use sui_types::base_types::SuiAddress;

use crate::handlers::sui_verify_msg::Message;
use crate::handlers::sui_verify_worker_set::WorkerSetConfirmation;
use crate::types::Hash;

#[derive(Deserialize)]
struct ContractCall {
    pub source_id: SuiAddress,
    pub destination_chain: String,
    pub destination_address: String,
    pub payload_hash: Hash,
}

#[derive(Deserialize)]
struct OperatorshipTransferred {
    pub payload: Vec<u8>,
}

enum EventType {
    ContractCall,
    OperatorshipTransferred,
}

impl EventType {
    // Sui event type  is in the form of: <address>::<module_name>::<event_name>
    fn struct_tag(&self, gateway_address: &SuiAddress) -> StructTag {
        let event = match self {
            EventType::ContractCall => "ContractCall",
            EventType::OperatorshipTransferred => "OperatorshipTransferred",
        };

        let module = match self {
            EventType::ContractCall => "gateway",
            EventType::OperatorshipTransferred => "validators",
        };

        format!("{}::{}::{}", gateway_address, module, event)
            .parse()
            .expect("failed to parse struct tag")
    }
}

impl PartialEq<&Message> for &SuiEvent {
    fn eq(&self, msg: &&Message) -> bool {
        match serde_json::from_value::<ContractCall>(self.parsed_json.clone()) {
            Ok(contract_call) => {
                contract_call.source_id == msg.source_address
                    && msg.destination_chain == contract_call.destination_chain
                    && contract_call.destination_address == msg.destination_address
                    && contract_call.payload_hash == msg.payload_hash
            }
            _ => false,
        }
    }
}

impl PartialEq<&WorkerSetConfirmation> for &SuiEvent {
    fn eq(&self, worker_set: &&WorkerSetConfirmation) -> bool {
        match serde_json::from_value::<OperatorshipTransferred>(self.parsed_json.clone()) {
            Ok(event) => {
                let (operators, weights): (Vec<_>, Vec<_>) = worker_set
                    .operators
                    .weights_by_addresses
                    .iter()
                    .map(|(operator, weight)| (operator.to_owned().to_vec(), weight.to_owned()))
                    .unzip();

                event.payload
                    == to_bytes(&(operators, weights, worker_set.operators.threshold))
                        .expect("failed to serialize new operators data")
            }
            _ => false,
        }
    }
}

fn find_event(
    transaction_block: &SuiTransactionBlockResponse,
    event_seq: u64,
) -> Option<&SuiEvent> {
    transaction_block
        .events
        .as_ref()
        .iter()
        .flat_map(|events| events.data.iter())
        .find(|event| event.id.event_seq == event_seq)
}

pub fn verify_message(
    gateway_address: &SuiAddress,
    transaction_block: &SuiTransactionBlockResponse,
    message: &Message,
) -> bool {
    match find_event(transaction_block, message.event_index) {
        Some(event) => {
            transaction_block.digest == message.tx_id
                && event.type_ == EventType::ContractCall.struct_tag(gateway_address)
                && event == message
        }
        None => false,
    }
}

pub fn verify_worker_set(
    gateway_address: &SuiAddress,
    transaction_block: &SuiTransactionBlockResponse,
    worker_set: &WorkerSetConfirmation,
) -> bool {
    match find_event(transaction_block, worker_set.event_index) {
        Some(event) => {
            transaction_block.digest == worker_set.tx_id
                && event.type_ == EventType::OperatorshipTransferred.struct_tag(gateway_address)
                && event == worker_set
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use ethers::abi::AbiEncode;
    use move_core_types::language_storage::StructTag;
    use random_string::generate;
    use sui_json_rpc_types::{SuiEvent, SuiTransactionBlockEvents, SuiTransactionBlockResponse};
    use sui_types::{
        base_types::{SuiAddress, TransactionDigest},
        event::EventID,
    };

    use connection_router::state::ChainName;

    use crate::handlers::sui_verify_msg::Message;
    use crate::sui::verifier::verify_message;
    use crate::types::{EVMAddress, Hash};

    #[test]
    fn should_not_verify_msg_if_tx_id_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_block();

        msg.tx_id = TransactionDigest::random();
        assert!(!verify_message(&gateway_address, &tx_receipt, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_event_index_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_block();

        msg.event_index = rand::random::<u64>();
        assert!(!verify_message(&gateway_address, &tx_receipt, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_source_address_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_block();

        msg.source_address = SuiAddress::random_for_testing_only();
        assert!(!verify_message(&gateway_address, &tx_receipt, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_destination_chain_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_block();

        msg.destination_chain = rand_chain_name();
        assert!(!verify_message(&gateway_address, &tx_receipt, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_destination_address_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_block();

        msg.destination_address = EVMAddress::random().to_string();
        assert!(!verify_message(&gateway_address, &tx_receipt, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_payload_hash_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_block();

        msg.payload_hash = Hash::random();
        assert!(!verify_message(&gateway_address, &tx_receipt, &msg));
    }

    #[test]
    fn should_verify_msg_if_correct() {
        let (gateway_address, tx_block, msg) = get_matching_msg_and_tx_block();
        assert!(verify_message(&gateway_address, &tx_block, &msg));
    }

    fn get_matching_msg_and_tx_block() -> (SuiAddress, SuiTransactionBlockResponse, Message) {
        let gateway_address = SuiAddress::random_for_testing_only();

        let msg = Message {
            tx_id: TransactionDigest::random(),
            event_index: rand::random::<u64>(),
            source_address: SuiAddress::random_for_testing_only(),
            destination_chain: rand_chain_name(),
            destination_address: format!("0x{:x}", EVMAddress::random()).parse().unwrap(),
            payload_hash: Hash::random(),
        };

        let json_str = format!(
            r#"{{"destination_address": "{}", "destination_chain": "{}",  "payload": "[1,2,3]",
            "payload_hash": "{}",  "source_id": "{}"}}"#,
            msg.destination_address,
            msg.destination_chain,
            msg.payload_hash.encode_hex(),
            msg.source_address
        );
        let parsed: serde_json::Value = serde_json::from_str(json_str.as_str()).unwrap();

        let event = SuiEvent {
            id: EventID {
                tx_digest: msg.tx_id,
                event_seq: msg.event_index,
            },
            package_id: gateway_address.into(),
            transaction_module: "gateway".parse().unwrap(),
            sender: msg.source_address,
            type_: StructTag {
                address: gateway_address.into(),
                module: "gateway".parse().unwrap(),
                name: "ContractCall".parse().unwrap(),
                type_params: vec![],
            },
            parsed_json: parsed,
            bcs: vec![],
            timestamp_ms: None,
        };

        let tx_block = SuiTransactionBlockResponse {
            digest: msg.tx_id,
            events: Some(SuiTransactionBlockEvents { data: vec![event] }),
            ..Default::default()
        };

        (gateway_address, tx_block, msg)
    }

    fn rand_chain_name() -> ChainName {
        let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        generate(8, charset).parse().unwrap()
    }
}
