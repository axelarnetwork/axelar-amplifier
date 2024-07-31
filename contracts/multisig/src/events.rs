use std::collections::HashMap;

use cosmwasm_std::{Addr, HexBinary, Uint64};
use router_api::ChainName;
use serde_json::to_string;

use crate::key::{PublicKey, Signature};
use crate::types::MsgToSign;

pub enum Event {
    // Emitted when a new signing session is open
    SigningStarted {
        session_id: Uint64,
        verifier_set_id: String,
        pub_keys: HashMap<String, PublicKey>,
        msg: MsgToSign,
        chain_name: ChainName,
        expires_at: u64,
    },
    // Emitted when a participant submits a signature
    SignatureSubmitted {
        session_id: Uint64,
        participant: Addr,
        signature: Signature,
    },
    // Emitted when a signing session was completed
    SigningCompleted {
        session_id: Uint64,
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

impl From<Event> for cosmwasm_std::Event {
    fn from(other: Event) -> Self {
        match other {
            Event::SigningStarted {
                session_id,
                verifier_set_id,
                pub_keys,
                msg,
                chain_name: chain,
                expires_at,
            } => cosmwasm_std::Event::new("signing_started")
                .add_attribute("session_id", session_id)
                .add_attribute("verifier_set_id", verifier_set_id)
                .add_attribute(
                    "pub_keys",
                    to_string(&pub_keys)
                        .expect("violated invariant: pub_keys are not serializable"),
                )
                .add_attribute("msg", HexBinary::from(msg).to_hex())
                .add_attribute("chain", chain)
                .add_attribute("expires_at", expires_at.to_string()),
            Event::SignatureSubmitted {
                session_id,
                participant,
                signature,
            } => cosmwasm_std::Event::new("signature_submitted")
                .add_attribute("session_id", session_id)
                .add_attribute("participant", participant)
                .add_attribute("signature", HexBinary::from(signature.as_ref()).to_hex()),
            Event::SigningCompleted {
                session_id,
                completed_at,
                chain_name,
            } => cosmwasm_std::Event::new("signing_completed")
                .add_attribute("session_id", session_id)
                .add_attribute("completed_at", completed_at.to_string())
                .add_attribute("chain", chain_name),
            Event::PublicKeyRegistered {
                verifier,
                public_key,
            } => cosmwasm_std::Event::new("public_key_registered")
                .add_attribute(
                    "verifier",
                    to_string(&verifier).expect("failed to serialize verifier"),
                )
                .add_attribute(
                    "public_key",
                    to_string(&public_key).expect("failed to serialize public key"),
                ),
            Event::CallerAuthorized {
                contract_address,
                chain_name,
            } => cosmwasm_std::Event::new("caller_authorized")
                .add_attribute("contract_address", contract_address)
                .add_attribute("chain_name", chain_name),
            Event::CallerUnauthorized {
                contract_address,
                chain_name,
            } => cosmwasm_std::Event::new("caller_unauthorized")
                .add_attribute("contract_address", contract_address)
                .add_attribute("chain_name", chain_name),
            Event::SigningEnabled => cosmwasm_std::Event::new("signing_enabled"),
            Event::SigningDisabled => cosmwasm_std::Event::new("signing_disabled"),
        }
    }
}
