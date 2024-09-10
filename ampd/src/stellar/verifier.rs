use std::str::FromStr;

use axelar_wasm_std::voting::Vote;
use stellar_xdr::curr::{ContractEventBody, ScAddress, ScSymbol, ScVal, StringM};

use crate::handlers::stellar_verify_msg::Message;
use crate::stellar::http_client::TxResponse;

const TOPIC_CALLED: &str = "called";

impl PartialEq<ContractEventBody> for Message {
    fn eq(&self, event: &ContractEventBody) -> bool {
        let ContractEventBody::V0(body) = event;

        if body.topics.len() != 3 {
            return false;
        }

        let [symbol, source_address, payload_hash] = &body.topics[..] else {
            return false;
        };

        let expected_topic: ScVal =
            ScSymbol(StringM::from_str(TOPIC_CALLED).expect("must convert str to ScSymbol")).into();

        let (dest_chain, dest_address) = match &body.data {
            ScVal::Vec(Some(data)) if data.len() == 3 => {
                let [dest_chain, dest_address, _] = &data[..] else {
                    return false;
                };
                (dest_chain, dest_address)
            }
            _ => return false,
        };

        expected_topic == *symbol
            && (ScVal::Address(self.source_address.clone()) == *source_address)
            && (ScVal::Bytes(self.payload_hash.clone()) == *payload_hash)
            && (ScVal::String(self.destination_chain.clone()) == *dest_chain)
            && (ScVal::String(self.destination_address.clone()) == *dest_address)
    }
}

pub fn verify_message(gateway_address: &ScAddress, tx_receipt: &TxResponse, msg: &Message) -> Vote {
    if tx_receipt.has_failed() {
        return Vote::FailedOnChain;
    }

    if msg.tx_id != tx_receipt.transaction_hash {
        return Vote::NotFound;
    }

    match tx_receipt.event(msg.event_index) {
        Some(event)
            if event
                .clone()
                .contract_id
                .is_some_and(|hash| ScAddress::Contract(hash) == *gateway_address)
                && msg == &event.body =>
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
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use stellar_xdr::curr::{
        AccountId, BytesM, ContractEvent, ContractEventBody, ContractEventType, ContractEventV0,
        PublicKey, ScAddress, ScBytes, ScString, ScSymbol, ScVal, StringM, Uint256,
    };

    use crate::handlers::stellar_verify_msg::Message;
    use crate::stellar::http_client::TxResponse;
    use crate::stellar::verifier::{verify_message, TOPIC_CALLED};
    use crate::types::{EVMAddress, Hash};

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
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
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

    fn matching_msg_and_tx_block() -> (ScAddress, TxResponse, Message) {
        let account_id = stellar_xdr::curr::Hash::from(Hash::random().0);
        let gateway_address = ScAddress::Contract(account_id.clone());

        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);

        let msg = Message {
            tx_id: Hash::random().to_string(),
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
                ScVal::Bytes(msg.payload_hash.clone()),
            ]
            .try_into()
            .unwrap(),
            data: ScVal::Vec(Some(
                vec![
                    ScVal::String(msg.destination_chain.clone()),
                    ScVal::String(msg.destination_address.clone()),
                    ScVal::String(StringM::from_str("payload").unwrap().into()),
                ]
                .try_into()
                .unwrap(),
            )),
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
}
