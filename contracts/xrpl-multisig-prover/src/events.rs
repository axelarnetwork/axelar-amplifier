use std::collections::HashMap;

use axelar_wasm_std::Snapshot;
use cosmwasm_std::{HexBinary, Uint64};
use serde_json::to_string;
use crate::types::TxHash;

pub enum Event {
    ProofUnderConstruction {
        tx_hash: TxHash,
        multisig_session_id: Uint64,
    },
    SnapshotRotated {
        key_id: String,
        snapshot: Snapshot,
        pub_keys: HashMap<String, HexBinary>,
    },
}

impl From<Event> for cosmwasm_std::Event {
    fn from(other: Event) -> Self {
        match other {
            Event::ProofUnderConstruction {
                tx_hash,
                multisig_session_id,
            } => cosmwasm_std::Event::new("proof_under_construction")
                .add_attribute(
                    "tx_hash",
                    to_string(&tx_hash)
                        .expect("violated invariant: tx_hash is not serializable"),
                )
                .add_attribute(
                    "multisig_session_id",
                    to_string(&multisig_session_id)
                        .expect("violated invariant: multisig_session_id is not serializable"),
                ),
            Event::SnapshotRotated {
                key_id,
                snapshot,
                pub_keys,
            } => cosmwasm_std::Event::new("snapshot_rotated")
                .add_attribute("key_id", key_id)
                .add_attribute(
                    "snapshot",
                    to_string(&snapshot).expect("violated invariant: snapshot is not serializable"),
                )
                .add_attribute(
                    "pub_keys",
                    to_string(&pub_keys)
                        .expect("violated invariant: pub_keys are not serializable"),
                ),
        }
    }
}
