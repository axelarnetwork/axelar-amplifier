use std::collections::HashMap;

use cosmwasm_std::{Addr, HexBinary, Uint64};
use serde_json::to_string;

use crate::types::{KeyID, Message, PublicKey, Signature};

pub enum Event {
    // Emitted when a new signing session is open
    SigningStarted {
        sig_id: Uint64,
        key_id: KeyID,
        pub_keys: HashMap<String, PublicKey>,
        msg: Message,
    },
    // Emitted when a participants submits a signature
    SignatureSubmitted {
        sig_id: Uint64,
        participant: Addr,
        signature: Signature,
    },
    // Emitted when a signing session was completed
    SigningCompleted {
        sig_id: Uint64,
    },
}

impl From<Event> for cosmwasm_std::Event {
    fn from(other: Event) -> Self {
        match other {
            Event::SigningStarted {
                sig_id,
                key_id,
                pub_keys,
                msg,
            } => cosmwasm_std::Event::new("signing_started")
                .add_attribute("sig_id", sig_id)
                .add_attribute("key_id", key_id.to_string())
                .add_attribute(
                    "pub_keys",
                    to_string(&pub_keys)
                        .expect("violated invariant: pub_keys are not serializable"),
                )
                .add_attribute("msg", HexBinary::from(msg).to_hex()),
            Event::SignatureSubmitted {
                sig_id,
                participant,
                signature,
            } => cosmwasm_std::Event::new("signature_submitted")
                .add_attribute("sig_id", sig_id)
                .add_attribute("participant", participant)
                .add_attribute("signature", HexBinary::from(signature).to_hex()),
            Event::SigningCompleted { sig_id } => {
                cosmwasm_std::Event::new("signing_completed").add_attribute("sig_id", sig_id)
            }
        }
    }
}
