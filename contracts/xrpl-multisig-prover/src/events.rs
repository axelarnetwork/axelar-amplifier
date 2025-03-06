use std::collections::HashMap;

use axelar_wasm_std::msg_id::HexTxHash;
use cosmwasm_std::{HexBinary, Uint64};
use multisig::key::PublicKey;
use router_api::ChainName;
use serde_json::to_string;

pub enum Event {
    ProofUnderConstruction {
        destination_chain: ChainName,
        unsigned_tx_hash: HexTxHash,
        multisig_session_id: Uint64,
    },
    XRPLSigningStarted {
        session_id: Uint64,
        verifier_set_id: String,
        pub_keys: HashMap<String, PublicKey>,
        unsigned_tx: HexBinary,
        expires_at: u64,
    },
}

impl From<Event> for cosmwasm_std::Event {
    fn from(other: Event) -> Self {
        match other {
            Event::ProofUnderConstruction {
                destination_chain,
                unsigned_tx_hash,
                multisig_session_id,
            } => cosmwasm_std::Event::new("proof_under_construction")
                .add_attribute(
                    "destination_chain",
                    to_string(&destination_chain)
                        .expect("violated invariant: destination_chain is not serializable"),
                )
                .add_attribute("unsigned_tx_hash", unsigned_tx_hash.to_string())
                .add_attribute(
                    "multisig_session_id",
                    to_string(&multisig_session_id)
                        .expect("violated invariant: multisig_session_id is not serializable"),
                ),
            Event::XRPLSigningStarted {
                session_id,
                verifier_set_id,
                pub_keys,
                unsigned_tx,
                expires_at,
            } => cosmwasm_std::Event::new("xrpl_signing_started")
                .add_attribute("session_id", session_id)
                .add_attribute("verifier_set_id", verifier_set_id)
                .add_attribute(
                    "pub_keys",
                    to_string(&pub_keys)
                        .expect("violated invariant: pub_keys are not serializable"),
                )
                .add_attribute("unsigned_tx", unsigned_tx.to_hex())
                .add_attribute("expires_at", expires_at.to_string()),
        }
    }
}
