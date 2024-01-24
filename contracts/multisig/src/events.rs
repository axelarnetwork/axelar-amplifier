use std::collections::HashMap;

use connection_router::state::ChainName;
use cosmwasm_std::{Addr, HexBinary, Uint64};
use serde_json::to_string;

use crate::{
    key::{PublicKey, Signature},
    types::MsgToSign,
};

pub enum Event {
    // Emitted when a new signing session is open
    SigningStarted {
        session_id: Uint64,
        worker_set_id: String,
        pub_keys: HashMap<String, PublicKey>,
        msg: MsgToSign,
        chain_name: ChainName,
        expires_at: u64,
    },
    // Emitted when a participants submits a signature
    SignatureSubmitted {
        session_id: Uint64,
        participant: Addr,
        signature: Signature,
    },
    // Emitted when a signing session was completed
    SigningCompleted {
        session_id: Uint64,
        completed_at: u64,
    },
    PublicKeyRegistered {
        worker: Addr,
        public_key: PublicKey,
    },
    CallerAuthorized {
        contract_address: Addr,
    },
    CallerUnauthorized {
        contract_address: Addr,
    },
}

impl From<Event> for cosmwasm_std::Event {
    fn from(other: Event) -> Self {
        match other {
            Event::SigningStarted {
                session_id,
                worker_set_id,
                pub_keys,
                msg,
                chain_name: chain,
                expires_at,
            } => cosmwasm_std::Event::new("signing_started")
                .add_attribute("session_id", session_id)
                .add_attribute("worker_set_id", worker_set_id)
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
            } => cosmwasm_std::Event::new("signing_completed")
                .add_attribute("session_id", session_id)
                .add_attribute("completed_at", completed_at.to_string()),
            Event::PublicKeyRegistered { worker, public_key } => {
                cosmwasm_std::Event::new("public_key_registered")
                    .add_attribute(
                        "worker",
                        to_string(&worker).expect("failed to serialize worker"),
                    )
                    .add_attribute(
                        "public_key",
                        to_string(&public_key).expect("failed to serialize public key"),
                    )
            }
            Event::CallerAuthorized { contract_address } => {
                cosmwasm_std::Event::new("caller_authorized")
                    .add_attribute("contract_address", contract_address)
            }
            Event::CallerUnauthorized { contract_address } => {
                cosmwasm_std::Event::new("caller_unauthorized")
                    .add_attribute("contract_address", contract_address)
            }
        }
    }
}
