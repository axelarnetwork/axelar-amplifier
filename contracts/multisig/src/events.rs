use std::collections::HashMap;

use cosmwasm_std::{Addr, HexBinary, Uint64};
use serde_json::to_string;

use crate::{
    key::{PublicKey, Signature},
    types::{KeyID, MsgToSign},
};

pub enum Event {
    // Emitted when a new signing session is open
    SigningStarted {
        session_id: Uint64,
        key_id: KeyID,
        pub_keys: HashMap<String, PublicKey>,
        msg: MsgToSign,
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
    },
    PublicKeyRegistered {
        worker: Addr,
        public_key: PublicKey,
    },
}

impl From<Event> for cosmwasm_std::Event {
    fn from(other: Event) -> Self {
        match other {
            Event::SigningStarted {
                session_id,
                key_id,
                pub_keys,
                msg,
            } => cosmwasm_std::Event::new("signing_started")
                .add_attribute("session_id", session_id)
                .add_attribute(
                    "key_id",
                    to_string(&key_id).expect("violated invariant: key id is not serializable"),
                )
                .add_attribute(
                    "pub_keys",
                    to_string(&pub_keys)
                        .expect("violated invariant: pub_keys are not serializable"),
                )
                .add_attribute("msg", HexBinary::from(msg).to_hex()),
            Event::SignatureSubmitted {
                session_id,
                participant,
                signature,
            } => cosmwasm_std::Event::new("signature_submitted")
                .add_attribute("session_id", session_id)
                .add_attribute("participant", participant)
                .add_attribute("signature", HexBinary::from(signature).to_hex()),
            Event::SigningCompleted { session_id } => cosmwasm_std::Event::new("signing_completed")
                .add_attribute("session_id", session_id),
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
        }
    }
}
