use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::voting::Vote;
use axelar_wasm_std::{self};
use cosmwasm_std::HexBinary;
use sui_gateway::events::{ContractCall, SignersRotated};
use sui_gateway::{WeightedSigner, WeightedSigners};
use sui_sdk_types::{Address, Event, StructTag};
use tracing::debug;

use crate::sui::transaction::Transaction;
use crate::sui::types::{Message, VerifierSetConfirmation};

enum EventType {
    ContractCall,
    SignersRotated,
}

impl EventType {
    // Sui event type  is in the form of: <address>::<module_name>::<event_name>
    fn struct_tag(&self, gateway_address: &Address) -> StructTag {
        let event = match self {
            EventType::ContractCall => "ContractCall",
            EventType::SignersRotated => "SignersRotated",
        };
        let module = "events";

        format!("{}::{}::{}", gateway_address, module, event)
            .parse()
            .expect("failed to parse struct tag")
    }
}

impl PartialEq<&Message> for &Event {
    fn eq(&self, msg: &&Message) -> bool {
        match bcs::from_bytes::<ContractCall>(&self.contents) {
            Ok(ContractCall {
                source_id,
                destination_chain,
                destination_address,
                payload_hash,
                ..
            }) => {
                let matches_destination_chain = match ChainName::try_from(destination_chain) {
                    Ok(chain) => msg.destination_chain == chain,
                    Err(e) => {
                        debug!(error = ?e, "failed to parse destination chain");
                        false
                    }
                };

                matches_destination_chain
                    && msg.source_address.as_bytes() == source_id.as_bytes()
                    && msg.destination_address == destination_address
                    && msg.payload_hash.to_fixed_bytes().to_vec() == payload_hash.to_vec()
            }
            _ => false,
        }
    }
}

impl PartialEq<&VerifierSetConfirmation> for &Event {
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

        match bcs::from_bytes::<SignersRotated>(&self.contents) {
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

// The event index of a message id is the event's position within the transaction's events
fn find_event(transaction_block: &Transaction, event_seq: u64) -> Option<&Event> {
    transaction_block
        .events
        .get(usize::try_from(event_seq).ok()?)
}

pub fn verify_message(
    gateway_address: &Address,
    transaction_block: &Transaction,
    message: &Message,
) -> Vote {
    match find_event(transaction_block, message.message_id.event_index) {
        Some(event)
            if transaction_block.digest == message.message_id.tx_digest.into()
                && event.type_ == EventType::ContractCall.struct_tag(gateway_address)
                && event == message =>
        {
            Vote::SucceededOnChain
        }
        _ => Vote::NotFound,
    }
}

pub fn verify_verifier_set(
    gateway_address: &Address,
    transaction_block: &Transaction,
    confirmation: &VerifierSetConfirmation,
) -> Vote {
    match find_event(transaction_block, confirmation.message_id.event_index) {
        Some(event)
            if transaction_block.digest == confirmation.message_id.tx_digest.into()
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
    use ampd::types::{CosmosPublicKey, EVMAddress, Hash};
    use axelar_wasm_std::msg_id::Base58TxDigestAndEventIndex;
    use axelar_wasm_std::voting::Vote;
    use cosmwasm_std::{Addr, HexBinary, Uint128};
    use multisig::key::KeyType;
    use multisig::msg::Signer;
    use multisig::verifier_set::VerifierSet;
    use rand::rngs::OsRng;
    use random_string::generate;
    use sui_gateway::events::{ContractCall, SignersRotated};
    use sui_gateway::{WeightedSigner, WeightedSigners};
    use sui_sdk_types::{Address, Digest, Event, Identifier, StructTag};

    use crate::sui::transaction::Transaction;
    use crate::sui::types::{Message, VerifierSetConfirmation};
    use crate::sui::verifier::{verify_message, verify_verifier_set, EventType};

    const PREFIX: &str = "axelar";

    #[test]
    fn should_not_verify_msg_if_tx_id_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = matching_msg_and_tx_block();

        msg.message_id.tx_digest = Digest::generate(rand::thread_rng()).into();
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_event_index_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = matching_msg_and_tx_block();

        msg.message_id.event_index = rand::random::<u64>();
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_another_event_is_at_the_index() {
        let (gateway_address, tx_receipt, mut msg) = matching_msg_and_tx_block();

        msg.message_id.event_index = 0;
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_source_address_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = matching_msg_and_tx_block();

        msg.source_address = Address::generate(rand::thread_rng());
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_destination_chain_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = matching_msg_and_tx_block();

        msg.destination_chain = rand_chain_name().parse().unwrap();
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
    fn should_verify_msg_if_chain_uses_different_casing() {
        let (gateway_address, tx_block, msg) = msg_and_tx_block_with_different_chain_casing();
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
                &Address::generate(rand::thread_rng()),
                &tx_block,
                &verifier_set
            ),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_tx_digest_mismatch() {
        let (gateway_address, mut tx_block, verifier_set) = matching_verifier_set_and_tx_block();
        tx_block.digest = Digest::generate(rand::thread_rng());

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx_block, &verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_event_seq_mismatch() {
        let (gateway_address, tx_block, mut verifier_set) = matching_verifier_set_and_tx_block();
        verifier_set.message_id.event_index = rand::random();

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
            .get_mut(usize::try_from(verifier_set.message_id.event_index).unwrap())
            .unwrap()
            .type_ = format!("{}::module::Name", Address::generate(rand::thread_rng()))
            .parse()
            .unwrap();

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

    // Index 1 or above, so another event always precedes the quoted one
    fn random_message_id() -> Base58TxDigestAndEventIndex {
        Base58TxDigestAndEventIndex::new(
            Digest::generate(rand::thread_rng()),
            u64::from(rand::random::<u8>()).max(1),
        )
    }

    // The event sits at the position given by the message id's event index
    fn mock_tx_block(message_id: &Base58TxDigestAndEventIndex, event: Event) -> Transaction {
        let other = mock_event("0x2::sui::SUI".parse().unwrap(), vec![]);
        let mut events = vec![other; usize::try_from(message_id.event_index).unwrap()];
        events.push(event);

        Transaction {
            digest: message_id.tx_digest.into(),
            events,
        }
    }

    fn mock_event(type_: StructTag, contents: Vec<u8>) -> Event {
        Event {
            package_id: Address::TWO,
            module: Identifier::from_static("events"),
            sender: Address::ZERO,
            type_,
            contents,
        }
    }

    fn mock_message(destination_chain: &str) -> Message {
        Message {
            message_id: random_message_id(),
            source_address: Address::generate(rand::thread_rng()),
            destination_chain: destination_chain.parse().unwrap(),
            destination_address: format!("0x{:x}", EVMAddress::random()).parse().unwrap(),
            payload_hash: Hash::random(),
        }
    }

    fn mock_msg_tx_block(
        destination_chain: &str,
        gateway_address: Address,
        msg: &Message,
    ) -> Transaction {
        let contract_call = ContractCall {
            destination_address: msg.destination_address.clone(),
            destination_chain: destination_chain.to_string(),
            payload: msg.payload_hash.to_fixed_bytes().to_vec(),
            payload_hash: msg.payload_hash.to_fixed_bytes(),
            source_id: msg.source_address.to_string().parse().unwrap(),
        };
        let event = mock_event(
            EventType::ContractCall.struct_tag(&gateway_address),
            bcs::to_bytes(&contract_call).unwrap(),
        );

        mock_tx_block(&msg.message_id, event)
    }

    fn matching_msg_and_tx_block() -> (Address, Transaction, Message) {
        let gateway_address = Address::generate(rand::thread_rng());

        let destination_chain = rand_chain_name();
        let msg = mock_message(&destination_chain);
        let tx_block = mock_msg_tx_block(&destination_chain, gateway_address, &msg);

        (gateway_address, tx_block, msg)
    }

    fn msg_and_tx_block_with_different_chain_casing() -> (Address, Transaction, Message) {
        let gateway_address = Address::generate(rand::thread_rng());

        let msg = mock_message("ethereum");
        let tx_block = mock_msg_tx_block("Ethereum", gateway_address, &msg);

        (gateway_address, tx_block, msg)
    }

    fn random_signer() -> Signer {
        let priv_key = k256::ecdsa::SigningKey::random(&mut OsRng);
        let pub_key: CosmosPublicKey = priv_key.verifying_key().into();
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

    fn matching_verifier_set_and_tx_block() -> (Address, Transaction, VerifierSetConfirmation) {
        let gateway_address = Address::generate(rand::thread_rng());
        let signers = vec![random_signer(), random_signer(), random_signer()];
        let created_at = rand::random();
        let threshold = Uint128::one();
        let verifier_set_confirmation = VerifierSetConfirmation {
            message_id: random_message_id(),
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
        let event = mock_event(
            EventType::SignersRotated.struct_tag(&gateway_address),
            bcs::to_bytes(&signers_rotated).unwrap(),
        );
        let tx_block = mock_tx_block(&verifier_set_confirmation.message_id, event);

        (gateway_address, tx_block, verifier_set_confirmation)
    }

    fn rand_chain_name() -> String {
        let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        generate(8, charset)
    }
}
