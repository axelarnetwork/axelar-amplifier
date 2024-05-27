use axelar_wasm_std::voting::Vote;
use move_core_types::language_storage::StructTag;
use serde::Deserialize;
use sui_json_rpc_types::{SuiEvent, SuiTransactionBlockResponse};
use sui_types::base_types::SuiAddress;

use crate::handlers::sui_verify_msg::Message;
use crate::handlers::sui_verify_verifier_set::VerifierSetConfirmation;
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
    #[allow(dead_code)]
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

impl PartialEq<&VerifierSetConfirmation> for &SuiEvent {
    fn eq(&self, _verifier_set: &&VerifierSetConfirmation) -> bool {
        match serde_json::from_value::<OperatorshipTransferred>(self.parsed_json.clone()) {
            Ok(_event) => {
                // TODO: convert verifier set to Sui gateway V2 WeightedSigners struct
                todo!()
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
) -> Vote {
    match find_event(transaction_block, message.event_index as u64) {
        Some(event)
            if transaction_block.digest == message.tx_id
                && event.type_ == EventType::ContractCall.struct_tag(gateway_address)
                && event == message =>
        {
            Vote::SucceededOnChain
        }
        _ => Vote::NotFound,
    }
}

pub fn verify_verifier_set(
    gateway_address: &SuiAddress,
    transaction_block: &SuiTransactionBlockResponse,
    confirmation: &VerifierSetConfirmation,
) -> Vote {
    match find_event(transaction_block, confirmation.event_index as u64) {
        Some(event)
            if transaction_block.digest == confirmation.tx_id
                && event.type_
                    == EventType::OperatorshipTransferred.struct_tag(gateway_address)
                && event == confirmation =>
        {
            Vote::SucceededOnChain
        }
        _ => Vote::NotFound,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use cosmwasm_std::Uint128;
    use ethers::abi::AbiEncode;
    use move_core_types::language_storage::StructTag;
    use random_string::generate;
    use sui_json_rpc_types::{SuiEvent, SuiTransactionBlockEvents, SuiTransactionBlockResponse};
    use sui_types::{
        base_types::{SuiAddress, TransactionDigest},
        event::EventID,
    };

    use axelar_wasm_std::voting::Vote;
    use multisig::verifier_set::VerifierSet;
    use router_api::ChainName;

    use crate::handlers::{
        sui_verify_msg::Message, sui_verify_verifier_set::VerifierSetConfirmation,
    };
    use crate::sui::verifier::{verify_message, verify_verifier_set};
    use crate::types::{EVMAddress, Hash};

    #[test]
    fn should_not_verify_msg_if_tx_id_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_block();

        msg.tx_id = TransactionDigest::random();
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_event_index_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_block();

        msg.event_index = rand::random::<u32>();
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_source_address_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_block();

        msg.source_address = SuiAddress::random_for_testing_only();
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_destination_chain_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_block();

        msg.destination_chain = rand_chain_name();
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_destination_address_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_block();

        msg.destination_address = EVMAddress::random().to_string();
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_payload_hash_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_block();

        msg.payload_hash = Hash::random();
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_verify_msg_if_correct() {
        let (gateway_address, tx_block, msg) = get_matching_msg_and_tx_block();
        assert_eq!(
            verify_message(&gateway_address, &tx_block, &msg),
            Vote::SucceededOnChain
        );
    }

    #[test]
    fn should_verify_verifier_set() {
        let (gateway_address, tx_receipt, verifier_set) = get_matching_verifier_set_and_tx_block();

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx_receipt, &verifier_set),
            Vote::SucceededOnChain
        );
    }

    fn get_matching_msg_and_tx_block() -> (SuiAddress, SuiTransactionBlockResponse, Message) {
        let gateway_address = SuiAddress::random_for_testing_only();

        let msg = Message {
            tx_id: TransactionDigest::random(),
            event_index: rand::random::<u32>(),
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
                event_seq: msg.event_index as u64,
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

    fn get_matching_verifier_set_and_tx_block() -> (
        SuiAddress,
        SuiTransactionBlockResponse,
        VerifierSetConfirmation,
    ) {
        let gateway_address = SuiAddress::random_for_testing_only();

        let verifier_set_confirmation = VerifierSetConfirmation {
            tx_id: TransactionDigest::random(),
            event_index: rand::random::<u32>(),
            verifier_set: VerifierSet {
                signers: BTreeMap::new(),
                threshold: Uint128::one(),
                created_at: 2,
            },
        };

        let json_str = format!(
            r#"{{"epoch": "{}", "payload":[9,33,2,28,79,35,229,96,199,254,112,157,252,157,33,86,76,80,174,125,71,132,149,100,185,195,50,28,56,168,173,27,148,211,13,33,2,48,84,180,104,180,217,232,81,68,34,87,5,170,93,208,110,70,34,106,18,170,230,232,84,177,96,70,223,39,33,69,243,33,2,111,165,50,83,196,229,202,139,167,22,144,71,12,136,118,134,248,101,250,219,73,67,12,46,149,223,204,58,134,78,12,140,33,2,117,97,196,77,216,94,31,8,169,159,77,164,26,249,18,252,106,73,134,164,49,179,32,156,241,200,236,219,119,96,154,174,33,2,211,238,247,108,49,105,73,69,232,85,66,59,29,114,68,216,13,187,208,76,45,190,112,127,63,78,201,189,207,232,137,80,33,2,253,243,145,109,216,125,193,53,124,210,124,157,62,195,2,187,26,78,51,29,236,222,0,247,71,157,177,44,59,201,201,110,33,3,13,71,41,67,81,196,128,14,128,66,129,231,226,77,127,173,123,58,83,198,102,149,143,165,189,207,7,26,146,127,120,223,33,3,179,111,82,200,141,104,219,127,177,163,157,28,106,41,141,191,105,54,200,199,63,140,125,57,134,20,90,19,183,153,55,68,33,3,250,161,172,32,115,91,220,86,71,57,15,155,185,167,99,209,57,194,132,114,11,176,91,70,232,219,84,202,119,5,157,125,9,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}}"#,
            rand::random::<u64>(),
        );
        let parsed: serde_json::Value = serde_json::from_str(json_str.as_str()).unwrap();

        let event = SuiEvent {
            id: EventID {
                tx_digest: verifier_set_confirmation.tx_id,
                event_seq: verifier_set_confirmation.event_index as u64,
            },
            package_id: gateway_address.into(),
            transaction_module: "gateway".parse().unwrap(),
            sender: SuiAddress::random_for_testing_only(),
            type_: StructTag {
                address: gateway_address.into(),
                module: "validators".parse().unwrap(),
                name: "OperatorshipTransferred".parse().unwrap(),
                type_params: vec![],
            },
            parsed_json: parsed,
            bcs: vec![],
            timestamp_ms: None,
        };

        let tx_block = SuiTransactionBlockResponse {
            digest: verifier_set_confirmation.tx_id,
            events: Some(SuiTransactionBlockEvents { data: vec![event] }),
            ..Default::default()
        };

        (gateway_address, tx_block, verifier_set_confirmation)
    }

    fn rand_chain_name() -> ChainName {
        let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        generate(8, charset).parse().unwrap()
    }
}
