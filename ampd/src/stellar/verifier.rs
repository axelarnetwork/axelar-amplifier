use std::str::FromStr;

use axelar_wasm_std::voting::Vote;
use router_api::ChainName;
use stellar::WeightedSigners;
use stellar_xdr::curr::{BytesM, ContractEventBody, ScAddress, ScBytes, ScSymbol, ScVal, StringM};
use tracing::debug;

use crate::handlers::stellar_verify_msg::Message;
use crate::handlers::stellar_verify_verifier_set::VerifierSetConfirmation;
use crate::stellar::rpc_client::TxResponse;

const TOPIC_CONTRACT_CALLED: &str = "contract_called";
const TOPIC_SIGNERS_ROTATED: &str = "signers_rotated";

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

        let expected_topic: ScVal = ScSymbol(
            StringM::from_str(TOPIC_CONTRACT_CALLED).expect("must convert str to ScSymbol"),
        )
        .into();

        let matches_destination_chain = match destination_chain {
            ScVal::String(s) => match ChainName::try_from(s.to_string()) {
                Ok(chain) => chain == self.destination_chain,
                Err(e) => {
                    debug!(error = ?e, "failed to parse destination chain");
                    false
                }
            },
            _ => false,
        };

        matches_destination_chain
            && expected_topic == *symbol
            && (ScVal::Address(self.source_address.clone()) == *source_address)
            && (ScVal::Bytes(self.payload_hash.clone()) == *payload_hash)
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

        let expected_topic: ScVal = ScSymbol(
            StringM::from_str(TOPIC_SIGNERS_ROTATED).expect("must convert str to ScSymbol"),
        )
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
        msg.message_id.tx_hash_as_hex_no_prefix().to_string(),
        msg.message_id.event_index,
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
        verifier_set_confirmation
            .message_id
            .tx_hash_as_hex_no_prefix()
            .to_string(),
        verifier_set_confirmation.message_id.event_index,
    )
}

fn verify<'a>(
    gateway_address: &ScAddress,
    tx_receipt: &'a TxResponse,
    to_verify: impl PartialEq<&'a ContractEventBody>,
    expected_tx_id: String,
    expected_event_index: u64,
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

    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelar_wasm_std::voting::Vote;
    use cosmrs::tx::MessageExt;
    use cosmwasm_std::{Addr, HexBinary, Uint128};
    use ed25519_dalek::SigningKey;
    use k256::elliptic_curve::rand_core::OsRng;
    use multisig::key::KeyType;
    use multisig::msg::Signer;
    use multisig::verifier_set::VerifierSet;
    use stellar::WeightedSigners;
    use stellar_xdr::curr::{
        AccountId, BytesM, ContractEvent, ContractEventBody, ContractEventType, ContractEventV0,
        PublicKey, ScAddress, ScBytes, ScString, ScSymbol, ScVal, StringM, Uint256,
    };

    use crate::handlers::stellar_verify_msg::Message;
    use crate::handlers::stellar_verify_verifier_set::VerifierSetConfirmation;
    use crate::stellar::rpc_client::TxResponse;
    use crate::stellar::verifier::{
        verify_message, verify_verifier_set, TOPIC_CONTRACT_CALLED, TOPIC_SIGNERS_ROTATED,
    };
    use crate::types::{CosmosPublicKey, EVMAddress, Hash};
    use crate::PREFIX;

    #[test]
    fn should_not_verify_msg_if_tx_id_does_not_match() {
        let (gateway_address, tx_response, mut msg) = matching_msg_and_tx_block();
        msg.message_id.tx_hash = Hash::random().into();

        assert_eq!(
            verify_message(&gateway_address, &tx_response, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_event_index_does_not_match() {
        let (gateway_address, tx_response, mut msg) = matching_msg_and_tx_block();
        msg.message_id.event_index = 1;

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
        msg.destination_chain = "different-chain".parse().unwrap();

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
    fn should_verify_msg_if_chain_uses_different_casing() {
        let (gateway_address, tx_response, msg) = msg_and_tx_response_with_different_chain_casing();

        assert_eq!(
            verify_message(&gateway_address, &tx_response, &msg),
            Vote::SucceededOnChain
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_tx_id_does_not_match() {
        let (gateway_address, tx_response, mut confirmation) = matching_verifier_set_and_tx_block();
        confirmation.message_id.tx_hash = Hash::random().into();

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx_response, &confirmation),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_event_index_does_not_match() {
        let (gateway_address, tx_response, mut confirmation) = matching_verifier_set_and_tx_block();
        confirmation.message_id.event_index = 1;

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

    fn mock_message(destination_chain: &str) -> Message {
        let signing_key = SigningKey::generate(&mut OsRng);

        Message {
            message_id: HexTxHashAndEventIndex::new(Hash::random(), 0u64),
            source_address: ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(
                Uint256::from(signing_key.verifying_key().to_bytes()),
            ))),
            destination_chain: destination_chain.parse().unwrap(),
            destination_address: ScString::from(
                StringM::try_from(format!("0x{:x}", EVMAddress::random()).to_bytes().unwrap())
                    .unwrap(),
            ),
            payload_hash: ScBytes(BytesM::try_from(Hash::random().to_fixed_bytes()).unwrap()),
        }
    }

    fn mock_tx_response(
        destination_chain: &str,
        account_id: stellar_xdr::curr::Hash,
        msg: &Message,
    ) -> TxResponse {
        let event_body = ContractEventBody::V0(ContractEventV0 {
            topics: vec![
                ScVal::Symbol(ScSymbol(StringM::from_str(TOPIC_CONTRACT_CALLED).unwrap())),
                ScVal::Address(msg.source_address.clone()),
                ScVal::String(ScString::from(
                    StringM::from_str(destination_chain).unwrap(),
                )),
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

        TxResponse {
            transaction_hash: msg.message_id.tx_hash_as_hex_no_prefix().to_string(),
            successful: true,
            contract_events: vec![event].try_into().unwrap(),
        }
    }

    fn matching_msg_and_tx_block() -> (ScAddress, TxResponse, Message) {
        let account_id = stellar_xdr::curr::Hash::from(Hash::random().0);
        let gateway_address = ScAddress::Contract(account_id.clone());

        let destination_chain = "ethereum";
        let msg = mock_message(destination_chain);
        let tx_response = mock_tx_response(destination_chain, account_id, &msg);

        (gateway_address, tx_response, msg)
    }

    fn msg_and_tx_response_with_different_chain_casing() -> (ScAddress, TxResponse, Message) {
        let account_id = stellar_xdr::curr::Hash::from(Hash::random().0);
        let gateway_address = ScAddress::Contract(account_id.clone());

        let msg = mock_message("ethereum");
        let tx_response = mock_tx_response("Ethereum", account_id, &msg);

        (gateway_address, tx_response, msg)
    }

    fn matching_verifier_set_and_tx_block() -> (ScAddress, TxResponse, VerifierSetConfirmation) {
        let account_id = stellar_xdr::curr::Hash::from(Hash::random().0);
        let gateway_address = ScAddress::Contract(account_id.clone());

        let signers = vec![random_signer(), random_signer(), random_signer()];
        let created_at = rand::random();
        let threshold = Uint128::new(2u128);

        let verifier_set_confirmation = VerifierSetConfirmation {
            message_id: HexTxHashAndEventIndex::new(Hash::random(), 0u64),
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
                ScVal::Symbol(ScSymbol(StringM::from_str(TOPIC_SIGNERS_ROTATED).unwrap())),
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
            transaction_hash: verifier_set_confirmation
                .message_id
                .tx_hash_as_hex_no_prefix()
                .to_string(),
            successful: true,
            contract_events: vec![event].try_into().unwrap(),
        };

        (gateway_address, tx_response, verifier_set_confirmation)
    }

    pub fn random_signer() -> Signer {
        let priv_key = k256::ecdsa::SigningKey::random(&mut OsRng);
        let pub_key: CosmosPublicKey = priv_key.verifying_key().into();

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
