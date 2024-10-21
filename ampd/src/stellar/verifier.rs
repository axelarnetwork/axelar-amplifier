use std::str::FromStr;

use axelar_wasm_std::voting::Vote;
use stellar::WeightedSigners;
use stellar_xdr::curr::{BytesM, ContractEventBody, ScAddress, ScBytes, ScSymbol, ScVal, StringM};

use crate::handlers::stellar_verify_msg::Message;
use crate::handlers::stellar_verify_verifier_set::VerifierSetConfirmation;
use crate::stellar::http_client::TxResponse;

const TOPIC_CALLED: &str = "called";
const TOPIC_ROTATED: &str = "rotated";

impl PartialEq<ContractEventBody> for Message {
    fn eq(&self, event: &ContractEventBody) -> bool {
        let ContractEventBody::V0(body) = event;

        if body.topics.len() != 5 {
            return false;
        }

        let [symbol, source_address, destination_chain, destination_address, payload_hash] =
            &body.topics[..]
        else {
            return false;
        };

        let expected_topic: ScVal =
            ScSymbol(StringM::from_str(TOPIC_CALLED).expect("must convert str to ScSymbol")).into();

        expected_topic == *symbol
            && (ScVal::Address(self.source_address.clone()) == *source_address)
            && (ScVal::Bytes(self.payload_hash.clone()) == *payload_hash)
            && (ScVal::String(self.destination_chain.clone()) == *destination_chain)
            && (ScVal::String(self.destination_address.clone()) == *destination_address)
    }
}

impl PartialEq<ContractEventBody> for VerifierSetConfirmation {
    fn eq(&self, event: &ContractEventBody) -> bool {
        let ContractEventBody::V0(body) = event;

        if body.topics.len() != 3 {
            return false;
        }

        let [symbol, _, signers_hash] = &body.topics[..] else {
            return false;
        };

        let expected_topic: ScVal =
            ScSymbol(StringM::from_str(TOPIC_ROTATED).expect("must convert str to ScSymbol"))
                .into();

        let Some(weighted_signers_hash) = WeightedSigners::try_from(&self.verifier_set)
            .ok()
            .and_then(|weighted_signers| weighted_signers.hash().ok())
            .and_then(|signers_hash| BytesM::try_from(signers_hash).ok())
            .map(ScBytes)
            .map(ScVal::Bytes)
        else {
            return false;
        };

        &expected_topic == symbol && &weighted_signers_hash == signers_hash
    }
}

pub fn verify_message(gateway_address: &ScAddress, tx_receipt: &TxResponse, msg: &Message) -> Vote {
    verify(
        gateway_address,
        tx_receipt,
        msg,
        msg.tx_id.clone(),
        msg.event_index,
    )
}

pub fn verify_verifier_set(
    gateway_address: &ScAddress,
    tx_receipt: &TxResponse,
    verifier_set_confirmation: &VerifierSetConfirmation,
) -> Vote {
    verify(
        gateway_address,
        tx_receipt,
        verifier_set_confirmation,
        verifier_set_confirmation.tx_id.clone(),
        verifier_set_confirmation.event_index,
    )
}

fn verify<'a>(
    gateway_address: &ScAddress,
    tx_receipt: &'a TxResponse,
    to_verify: impl PartialEq<&'a ContractEventBody>,
    expected_tx_id: String,
    expected_event_index: u32,
) -> Vote {
    if expected_tx_id != tx_receipt.transaction_hash {
        return Vote::NotFound;
    }

    if tx_receipt.has_failed() {
        return Vote::FailedOnChain;
    }

    match tx_receipt.event(expected_event_index) {
        Some(event)
            if event
                .clone()
                .contract_id
                .is_some_and(|hash| ScAddress::Contract(hash) == *gateway_address)
                && to_verify == &event.body =>
        {
            Vote::SucceededOnChain
        }
        _ => Vote::NotFound,
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use axelar_wasm_std::voting::Vote;
    use cosmrs::tx::MessageExt;
    use cosmwasm_std::{Addr, HexBinary, Uint128};
    use ed25519_dalek::SigningKey;
    use multisig::key::KeyType;
    use multisig::msg::Signer;
    use multisig::verifier_set::VerifierSet;
    use rand::rngs::OsRng;
    use stellar::WeightedSigners;
    use stellar_xdr::curr::{
        AccountId, BytesM, ContractEvent, ContractEventBody, ContractEventType, ContractEventV0,
        PublicKey, ScAddress, ScBytes, ScString, ScSymbol, ScVal, StringM, Uint256,
    };

    use crate::handlers::stellar_verify_msg::Message;
    use crate::handlers::stellar_verify_verifier_set::VerifierSetConfirmation;
    use crate::stellar::http_client::TxResponse;
    use crate::stellar::verifier::{
        verify_message, verify_verifier_set, TOPIC_CALLED, TOPIC_ROTATED,
    };
    use crate::types::{EVMAddress, Hash};
    use crate::PREFIX;

    #[test]
    fn should_not_verify_msg_if_tx_id_does_not_match() {
        let (gateway_address, tx_response, mut msg) = matching_msg_and_tx_block();
        msg.tx_id = "different_tx_hash".to_string();

        assert_eq!(
            verify_message(&gateway_address, &tx_response, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_event_index_does_not_match() {
        let (gateway_address, tx_response, mut msg) = matching_msg_and_tx_block();
        msg.event_index = 1;

        assert_eq!(
            verify_message(&gateway_address, &tx_response, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_source_address_does_not_match() {
        let (gateway_address, tx_response, mut msg) = matching_msg_and_tx_block();

        // Generate a different source address
        let signing_key = SigningKey::generate(&mut OsRng);
        let account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256::from(
            signing_key.verifying_key().to_bytes(),
        )));
        msg.source_address = ScAddress::Account(account_id);

        assert_eq!(
            verify_message(&gateway_address, &tx_response, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_destination_chain_does_not_match() {
        let (gateway_address, tx_response, mut msg) = matching_msg_and_tx_block();
        msg.destination_chain = ScString::from(StringM::from_str("different-chain").unwrap());

        assert_eq!(
            verify_message(&gateway_address, &tx_response, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_destination_address_does_not_match() {
        let (gateway_address, tx_response, mut msg) = matching_msg_and_tx_block();
        msg.destination_address = ScString::from(
            StringM::try_from(format!("0x{:x}", EVMAddress::random()).to_bytes().unwrap()).unwrap(),
        );

        assert_eq!(
            verify_message(&gateway_address, &tx_response, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_payload_hash_does_not_match() {
        let (gateway_address, tx_response, mut msg) = matching_msg_and_tx_block();
        msg.payload_hash = ScBytes(BytesM::try_from(Hash::random().to_fixed_bytes()).unwrap());

        assert_eq!(
            verify_message(&gateway_address, &tx_response, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_verify_msg_if_correct() {
        let (gateway_address, tx_response, msg) = matching_msg_and_tx_block();

        assert_eq!(
            verify_message(&gateway_address, &tx_response, &msg),
            Vote::SucceededOnChain
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_tx_id_does_not_match() {
        let (gateway_address, tx_response, mut confirmation) = matching_verifier_set_and_tx_block();
        confirmation.tx_id = "different_tx_hash".to_string();

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx_response, &confirmation),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_event_index_does_not_match() {
        let (gateway_address, tx_response, mut confirmation) = matching_verifier_set_and_tx_block();
        confirmation.event_index = 1;

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx_response, &confirmation),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_signer_hash_does_not_match() {
        let (gateway_address, tx_response, mut confirmation) = matching_verifier_set_and_tx_block();

        let signers = vec![random_signer(), random_signer(), random_signer()];
        confirmation.verifier_set = VerifierSet {
            signers: signers
                .iter()
                .map(|signer| (signer.address.to_string(), signer.clone()))
                .collect(),
            threshold: Uint128::new(2u128),
            created_at: rand::random(),
        };

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx_response, &confirmation),
            Vote::NotFound
        );
    }

    #[test]
    fn should_verify_verifier_set_if_correct() {
        let (gateway_address, tx_response, confirmation) = matching_verifier_set_and_tx_block();

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx_response, &confirmation),
            Vote::SucceededOnChain
        );
    }

    fn matching_msg_and_tx_block() -> (ScAddress, TxResponse, Message) {
        let account_id = stellar_xdr::curr::Hash::from(Hash::random().0);
        let gateway_address = ScAddress::Contract(account_id.clone());

        let signing_key = SigningKey::generate(&mut OsRng);

        let msg = Message {
            tx_id: format!("{:x}", Hash::random()),
            event_index: 0,
            source_address: ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(
                Uint256::from(signing_key.verifying_key().to_bytes()),
            ))),
            destination_chain: ScString::from(StringM::from_str("ethereum").unwrap()),
            destination_address: ScString::from(
                StringM::try_from(format!("0x{:x}", EVMAddress::random()).to_bytes().unwrap())
                    .unwrap(),
            ),
            payload_hash: ScBytes(BytesM::try_from(Hash::random().to_fixed_bytes()).unwrap()),
        };

        let event_body = ContractEventBody::V0(ContractEventV0 {
            topics: vec![
                ScVal::Symbol(ScSymbol(StringM::from_str(TOPIC_CALLED).unwrap())),
                ScVal::Address(msg.source_address.clone()),
                ScVal::String(msg.destination_chain.clone()),
                ScVal::String(msg.destination_address.clone()),
                ScVal::Bytes(msg.payload_hash.clone()),
            ]
            .try_into()
            .unwrap(),
            data: ScVal::Bytes(BytesM::try_from("payload".as_bytes()).unwrap().into()),
        });

        let event = ContractEvent {
            ext: stellar_xdr::curr::ExtensionPoint::V0,
            contract_id: Some(account_id),
            type_: ContractEventType::Contract,
            body: event_body,
        };

        let tx_response = TxResponse {
            transaction_hash: msg.tx_id.clone(),
            source_address: msg.source_address.clone(),
            successful: true,
            contract_events: Some(vec![event].try_into().unwrap()),
        };

        (gateway_address, tx_response, msg)
    }

    fn matching_verifier_set_and_tx_block() -> (ScAddress, TxResponse, VerifierSetConfirmation) {
        let account_id = stellar_xdr::curr::Hash::from(Hash::random().0);
        let gateway_address = ScAddress::Contract(account_id.clone());

        let signers = vec![random_signer(), random_signer(), random_signer()];
        let created_at = rand::random();
        let threshold = Uint128::new(2u128);

        let verifier_set_confirmation = VerifierSetConfirmation {
            tx_id: format!("{:x}", Hash::random()),
            event_index: 0,
            verifier_set: VerifierSet {
                signers: signers
                    .iter()
                    .map(|signer| (signer.address.to_string(), signer.clone()))
                    .collect(),
                threshold,
                created_at,
            },
        };

        let weighted_signers_hash = BytesM::try_from(
            WeightedSigners::try_from(&verifier_set_confirmation.verifier_set)
                .unwrap()
                .hash()
                .unwrap(),
        )
        .unwrap();

        let event_body = ContractEventBody::V0(ContractEventV0 {
            topics: vec![
                ScVal::Symbol(ScSymbol(StringM::from_str(TOPIC_ROTATED).unwrap())),
                ScVal::U64(1),
                ScVal::Bytes(ScBytes(weighted_signers_hash)),
            ]
            .try_into()
            .unwrap(),
            data: ().into(),
        });

        let event = ContractEvent {
            ext: stellar_xdr::curr::ExtensionPoint::V0,
            contract_id: Some(account_id),
            type_: ContractEventType::Contract,
            body: event_body,
        };

        let tx_response = TxResponse {
            transaction_hash: verifier_set_confirmation.tx_id.clone(),
            source_address: ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(
                Uint256::from(SigningKey::generate(&mut OsRng).verifying_key().to_bytes()),
            ))),
            successful: true,
            contract_events: Some(vec![event].try_into().unwrap()),
        };

        (gateway_address, tx_response, verifier_set_confirmation)
    }

    pub fn random_signer() -> Signer {
        let priv_key: ecdsa::SigningKey<k256::Secp256k1> = ecdsa::SigningKey::random(&mut OsRng);
        let pub_key: cosmrs::crypto::PublicKey = priv_key.verifying_key().into();

        let ed25519_pub_key = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();

        Signer {
            address: Addr::unchecked(pub_key.account_id(PREFIX).unwrap()),
            weight: Uint128::one(),
            pub_key: (KeyType::Ed25519, HexBinary::from(ed25519_pub_key))
                .try_into()
                .unwrap(),
        }
    }
}
