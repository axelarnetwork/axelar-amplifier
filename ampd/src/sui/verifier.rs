use axelar_wasm_std::voting::Vote;
use axelar_wasm_std::{self};
use cosmwasm_std::HexBinary;
use move_core_types::language_storage::StructTag;
use sui_gateway::events::{ContractCall, SignersRotated};
use sui_gateway::{WeightedSigner, WeightedSigners};
use sui_json_rpc_types::{SuiEvent, SuiTransactionBlockResponse};
use sui_types::base_types::SuiAddress;

use crate::handlers::sui_verify_msg::Message;
use crate::handlers::sui_verify_verifier_set::VerifierSetConfirmation;

enum EventType {
    ContractCall,
    SignersRotated,
}

impl EventType {
    // Sui event type  is in the form of: <address>::<module_name>::<event_name>
    fn struct_tag(&self, gateway_address: &SuiAddress) -> StructTag {
        let event = match self {
            EventType::ContractCall => "ContractCall",
            EventType::SignersRotated => "SignersRotated",
        };

        let module = match self {
            EventType::ContractCall => "gateway",
            EventType::SignersRotated => "auth",
        };

        format!("{}::{}::{}", gateway_address, module, event)
            .parse()
            .expect("failed to parse struct tag")
    }
}

impl PartialEq<&Message> for &SuiEvent {
    fn eq(&self, msg: &&Message) -> bool {
        match bcs::from_bytes::<ContractCall>(&self.bcs) {
            Ok(ContractCall {
                source_id,
                destination_chain,
                destination_address,
                payload_hash,
                ..
            }) => {
                msg.source_address.as_ref() == source_id.as_bytes()
                    && msg.destination_chain == destination_chain
                    && msg.destination_address == destination_address
                    && msg.payload_hash.to_fixed_bytes().to_vec() == payload_hash.to_vec()
            }
            _ => false,
        }
    }
}

impl PartialEq<&VerifierSetConfirmation> for &SuiEvent {
    fn eq(&self, verifier_set: &&VerifierSetConfirmation) -> bool {
        let expected = &verifier_set.verifier_set;

        let mut expected_signers = expected
            .signers
            .values()
            .map(|signer| WeightedSigner {
                pub_key: HexBinary::from(signer.pub_key.clone()).to_vec(),
                weight: signer.weight.u128(),
            })
            .collect::<Vec<_>>();
        expected_signers.sort();

        let expected_created_at = [0u8; 24]
            .into_iter()
            .chain(expected.created_at.to_be_bytes())
            .collect::<Vec<_>>();

        match bcs::from_bytes::<SignersRotated>(&self.bcs) {
            Ok(SignersRotated {
                signers:
                    WeightedSigners {
                        mut signers,
                        threshold,
                        nonce,
                    },
                ..
            }) => {
                signers.sort();

                signers == expected_signers
                    && threshold == expected.threshold.u128()
                    && nonce.as_ref() == expected_created_at.as_slice()
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
                && event.type_ == EventType::SignersRotated.struct_tag(gateway_address)
                && event == confirmation =>
        {
            Vote::SucceededOnChain
        }
        _ => Vote::NotFound,
    }
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::voting::Vote;
    use cosmrs::crypto::PublicKey;
    use cosmwasm_std::{Addr, HexBinary, Uint128};
    use ecdsa::SigningKey;
    use move_core_types::language_storage::StructTag;
    use multisig::key::KeyType;
    use multisig::msg::Signer;
    use multisig::verifier_set::VerifierSet;
    use rand::rngs::OsRng;
    use random_string::generate;
    use router_api::ChainName;
    use serde_json::json;
    use sui_gateway::events::{ContractCall, SignersRotated};
    use sui_gateway::{WeightedSigner, WeightedSigners};
    use sui_json_rpc_types::{SuiEvent, SuiTransactionBlockEvents, SuiTransactionBlockResponse};
    use sui_types::base_types::{SuiAddress, TransactionDigest};
    use sui_types::event::EventID;

    use crate::handlers::sui_verify_msg::Message;
    use crate::handlers::sui_verify_verifier_set::VerifierSetConfirmation;
    use crate::sui::verifier::{verify_message, verify_verifier_set};
    use crate::types::{EVMAddress, Hash};
    use crate::PREFIX;

    #[test]
    fn should_not_verify_msg_if_tx_id_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = matching_msg_and_tx_block();

        msg.tx_id = TransactionDigest::random();
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_event_index_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = matching_msg_and_tx_block();

        msg.event_index = rand::random::<u32>();
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_source_address_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = matching_msg_and_tx_block();

        msg.source_address = SuiAddress::random_for_testing_only();
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_destination_chain_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = matching_msg_and_tx_block();

        msg.destination_chain = rand_chain_name();
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_destination_address_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = matching_msg_and_tx_block();

        msg.destination_address = EVMAddress::random().to_string();
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_payload_hash_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = matching_msg_and_tx_block();

        msg.payload_hash = Hash::random();
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_verify_msg_if_correct() {
        let (gateway_address, tx_block, msg) = matching_msg_and_tx_block();
        assert_eq!(
            verify_message(&gateway_address, &tx_block, &msg),
            Vote::SucceededOnChain
        );
    }

    #[test]
    fn should_verify_verifier_set_if_correct() {
        let (gateway_address, tx_block, verifier_set) = matching_verifier_set_and_tx_block();

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx_block, &verifier_set),
            Vote::SucceededOnChain
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_gateway_address_mismatch() {
        let (_, tx_block, verifier_set) = matching_verifier_set_and_tx_block();

        assert_eq!(
            verify_verifier_set(
                &SuiAddress::random_for_testing_only(),
                &tx_block,
                &verifier_set
            ),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_tx_digest_mismatch() {
        let (gateway_address, mut tx_block, verifier_set) = matching_verifier_set_and_tx_block();
        tx_block.digest = TransactionDigest::random();

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx_block, &verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_event_seq_mismatch() {
        let (gateway_address, tx_block, mut verifier_set) = matching_verifier_set_and_tx_block();
        verifier_set.event_index = rand::random();

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx_block, &verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_struct_tag_mismatch() {
        let (gateway_address, mut tx_block, verifier_set) = matching_verifier_set_and_tx_block();
        tx_block
            .events
            .as_mut()
            .unwrap()
            .data
            .first_mut()
            .unwrap()
            .type_ = StructTag {
            address: SuiAddress::random_for_testing_only().into(),
            module: "module".parse().unwrap(),
            name: "Name".parse().unwrap(),
            type_params: vec![],
        };

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx_block, &verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_threshold_mismatch() {
        let (gateway_address, tx_block, mut verifier_set) = matching_verifier_set_and_tx_block();
        verifier_set.verifier_set.threshold = Uint128::new(2);

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx_block, &verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_nonce_mismatch() {
        let (gateway_address, tx_block, mut verifier_set) = matching_verifier_set_and_tx_block();
        verifier_set.verifier_set.created_at = rand::random();

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx_block, &verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_signers_mismatch() {
        let (gateway_address, tx_block, mut verifier_set) = matching_verifier_set_and_tx_block();
        let signer = random_signer();
        verifier_set
            .verifier_set
            .signers
            .insert(signer.address.to_string(), signer);

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx_block, &verifier_set),
            Vote::NotFound
        );
    }

    fn matching_msg_and_tx_block() -> (SuiAddress, SuiTransactionBlockResponse, Message) {
        let gateway_address = SuiAddress::random_for_testing_only();

        let msg = Message {
            tx_id: TransactionDigest::random(),
            event_index: rand::random::<u32>(),
            source_address: SuiAddress::random_for_testing_only(),
            destination_chain: rand_chain_name(),
            destination_address: format!("0x{:x}", EVMAddress::random()).parse().unwrap(),
            payload_hash: Hash::random(),
        };

        let contract_call = ContractCall {
            destination_address: msg.destination_address.clone(),
            destination_chain: msg.destination_chain.to_string(),
            payload: msg.payload_hash.to_fixed_bytes().to_vec(),
            payload_hash: msg.payload_hash.to_fixed_bytes(),
            source_id: msg.source_address.to_string().parse().unwrap(),
        };
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
            parsed_json: json!({}),
            bcs: bcs::to_bytes(&contract_call).unwrap(),
            timestamp_ms: None,
        };

        let tx_block = SuiTransactionBlockResponse {
            digest: msg.tx_id,
            events: Some(SuiTransactionBlockEvents { data: vec![event] }),
            ..Default::default()
        };

        (gateway_address, tx_block, msg)
    }

    fn random_signer() -> Signer {
        let priv_key = SigningKey::random(&mut OsRng);
        let pub_key: PublicKey = priv_key.verifying_key().into();
        let address = Addr::unchecked(pub_key.account_id(PREFIX).unwrap());
        let pub_key = (KeyType::Ecdsa, HexBinary::from(pub_key.to_bytes()))
            .try_into()
            .unwrap();

        Signer {
            address,
            weight: Uint128::one(),
            pub_key,
        }
    }

    fn matching_verifier_set_and_tx_block() -> (
        SuiAddress,
        SuiTransactionBlockResponse,
        VerifierSetConfirmation,
    ) {
        let gateway_address = SuiAddress::random_for_testing_only();
        let signers = vec![random_signer(), random_signer(), random_signer()];
        let created_at = rand::random();
        let threshold = Uint128::one();
        let verifier_set_confirmation = VerifierSetConfirmation {
            tx_id: TransactionDigest::random(),
            event_index: rand::random(),
            verifier_set: VerifierSet {
                signers: signers
                    .iter()
                    .map(|signer| (signer.address.to_string(), signer.clone()))
                    .collect(),
                threshold,
                created_at,
            },
        };

        let signers_rotated = SignersRotated {
            epoch: 0,
            signers_hash: [0; 32].into(),
            signers: WeightedSigners {
                signers: signers
                    .into_iter()
                    .map(|signer| WeightedSigner {
                        pub_key: HexBinary::from(signer.pub_key).to_vec(),
                        weight: signer.weight.u128(),
                    })
                    .collect(),
                threshold: threshold.u128(),
                nonce: <[u8; 32]>::try_from(
                    [0u8; 24]
                        .into_iter()
                        .chain(created_at.to_be_bytes())
                        .collect::<Vec<_>>(),
                )
                .unwrap()
                .into(),
            },
        };
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
                module: "auth".parse().unwrap(),
                name: "SignersRotated".parse().unwrap(),
                type_params: vec![],
            },
            parsed_json: json!({}),
            bcs: bcs::to_bytes(&signers_rotated).unwrap(),
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
