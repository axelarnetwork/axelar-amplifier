use std::collections::HashMap;

use cosmwasm_std::{Addr, HexBinary, Uint64};
use serde_json::to_string;

pub enum Event {
    // Emitted when a new signing session is open
    SigningStarted {
        multisig_session_id: Uint64,
        key_set_id: Uint64,
        pub_keys: HashMap<String, HexBinary>,
        sig_msg: HexBinary,
    },
    // Emitted when a participants submits a signature
    SignatureSubmitted {
        multisig_session_id: Uint64,
        participant: Addr,
        signature: HexBinary,
    },
    // Emitted when a signing session was completed
    SigningCompleted {
        multisig_session_id: Uint64,
    },
}

impl From<Event> for cosmwasm_std::Event {
    fn from(other: Event) -> Self {
        match other {
            Event::SigningStarted {
                multisig_session_id,
                key_set_id,
                pub_keys,
                sig_msg,
            } => cosmwasm_std::Event::new("signing_started")
                .add_attribute("multisig_session_id", multisig_session_id)
                .add_attribute("key_set_id", key_set_id)
                .add_attribute(
                    "pub_keys",
                    to_string(&pub_keys)
                        .expect("violated invariant: pub_keys are not serializable"),
                )
                .add_attribute("sig_msg", sig_msg.to_hex()),
            Event::SignatureSubmitted {
                multisig_session_id,
                participant,
                signature,
            } => cosmwasm_std::Event::new("signature_submitted")
                .add_attribute("multisig_session_id", multisig_session_id)
                .add_attribute("participant", participant)
                .add_attribute("signature", signature.to_hex()),
            Event::SigningCompleted {
                multisig_session_id,
            } => cosmwasm_std::Event::new("signing_completed")
                .add_attribute("multisig_session_id", multisig_session_id),
        }
    }
}
