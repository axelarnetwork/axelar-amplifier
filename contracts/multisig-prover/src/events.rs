use cosmwasm_std::Uint64;
use serde_json::to_string;

use crate::types::BatchID;

pub enum Event {
    ProofUnderConstruction {
        command_batch_id: BatchID,
        multisig_session_id: Uint64,
    },
}

impl From<Event> for cosmwasm_std::Event {
    fn from(other: Event) -> Self {
        match other {
            Event::ProofUnderConstruction {
                command_batch_id,
                multisig_session_id,
            } => cosmwasm_std::Event::new("proof_under_construction")
                .add_attribute(
                    "command_batch_id",
                    to_string(&command_batch_id)
                        .expect("violated invariant: command_batch_id is not serializable"),
                )
                .add_attribute(
                    "multisig_session_id",
                    to_string(&multisig_session_id)
                        .expect("violated invariant: multisig_session_id is not serializable"),
                ),
        }
    }
}
