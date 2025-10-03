use std::collections::HashMap;

use axelar_wasm_std::IntoEvent;
use cosmwasm_std::Addr;
use router_api::ChainName;

use crate::key::{PublicKey, Signature};
use crate::types::MsgToSign;

#[derive(IntoEvent)]
pub enum Event {
    // Emitted when a new signing session is open
    SigningStarted {
        session_id: u64,
        verifier_set_id: String,
        pub_keys: HashMap<String, PublicKey>,
        msg: MsgToSign,
        chain: ChainName,
        expires_at: u64,
    },
    // Emitted when a participant submits a signature
    SignatureSubmitted {
        session_id: u64,
        participant: Addr,
        signature: Signature,
    },
    // Emitted when a signing session was completed
    SigningCompleted {
        session_id: u64,
        completed_at: u64,
        chain_name: ChainName,
    },
    PublicKeyRegistered {
        verifier: Addr,
        public_key: PublicKey,
    },
    CallerAuthorized {
        contract_address: Addr,
        chain_name: ChainName,
    },
    CallerUnauthorized {
        contract_address: Addr,
        chain_name: ChainName,
    },
    SigningEnabled,
    SigningDisabled,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use cosmwasm_std::HexBinary;

    use super::*;

    #[test]
    fn signing_started_is_serializable() {
        let mut pub_keys = BTreeMap::new();
        pub_keys.insert(
            "verifier1".to_string(),
            PublicKey::Ecdsa(
                HexBinary::from_hex(
                    "02a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7",
                )
                .unwrap(),
            ),
        );
        pub_keys.insert(
            "verifier2".to_string(),
            PublicKey::Ed25519(
                HexBinary::from_hex(
                    "d75a980182b10c7d15b61f9b6f484d2c7b3307f1b1c0c9c0c9c0c9c0c9c0c9c0c9",
                )
                .unwrap(),
            ),
        );

        let event = Event::SigningStarted {
            session_id: 1u64,
            verifier_set_id: "verifier_set_1".to_string(),
            pub_keys: pub_keys.into_iter().collect(),
            msg: MsgToSign::unchecked(HexBinary::from_hex("deadbeef").unwrap()),
            chain: "ethereum".parse().unwrap(),
            expires_at: 1234567890,
        };
        let event = cosmwasm_std::Event::from(event);

        goldie::assert_json!(event);
    }

    #[test]
    fn signature_submitted_is_serializable() {
        let event = Event::SignatureSubmitted {
            session_id: 1u64,
            participant: Addr::unchecked("verifier1"),
            signature: Signature::Ecdsa(HexBinary::from([0; 64]).try_into().unwrap()),
        };
        let event = cosmwasm_std::Event::from(event);

        goldie::assert_json!(event);
    }

    #[test]
    fn signing_completed_is_serializable() {
        let event = Event::SigningCompleted {
            session_id: 1u64,
            completed_at: 1234567890,
            chain_name: "ethereum".parse().unwrap(),
        };
        let event = cosmwasm_std::Event::from(event);

        goldie::assert_json!(event);
    }

    #[test]
    fn public_key_registered_is_serializable() {
        let event = Event::PublicKeyRegistered {
            verifier: Addr::unchecked("verifier1"),
            public_key: PublicKey::Ecdsa(
                HexBinary::from_hex(
                    "02a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7",
                )
                .unwrap(),
            ),
        };
        let event = cosmwasm_std::Event::from(event);

        goldie::assert_json!(event);
    }

    #[test]
    fn caller_authorized_is_serializable() {
        let event = Event::CallerAuthorized {
            contract_address: Addr::unchecked("contract1"),
            chain_name: "ethereum".parse().unwrap(),
        };
        let event = cosmwasm_std::Event::from(event);

        goldie::assert_json!(event);
    }

    #[test]
    fn caller_unauthorized_is_serializable() {
        let event = Event::CallerUnauthorized {
            contract_address: Addr::unchecked("contract1"),
            chain_name: "ethereum".parse().unwrap(),
        };
        let event = cosmwasm_std::Event::from(event);

        goldie::assert_json!(event);
    }

    #[test]
    fn signing_enabled_is_serializable() {
        let event = Event::SigningEnabled;
        let event = cosmwasm_std::Event::from(event);

        goldie::assert_json!(event);
    }

    #[test]
    fn signing_disabled_is_serializable() {
        let event = Event::SigningDisabled;
        let event = cosmwasm_std::Event::from(event);

        goldie::assert_json!(event);
    }
}
