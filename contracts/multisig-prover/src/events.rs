use crate::types::BatchId;
use cosmwasm_std::Uint64;
use router_api::{ChainName, CrossChainId};

pub enum Event {
    ProofUnderConstruction {
        destination_chain: ChainName,
        command_batch_id: BatchId,
        multisig_session_id: Uint64,
        msg_ids: Vec<CrossChainId>,
    },
}

impl From<Event> for cosmwasm_std::Event {
    fn from(other: Event) -> Self {
        match other {
            Event::ProofUnderConstruction {
                destination_chain,
                command_batch_id,
                multisig_session_id,
                msg_ids,
            } => cosmwasm_std::Event::new("proof_under_construction")
                .add_attribute(
                    "destination_chain",
                    serde_json::to_string(&destination_chain)
                        .expect("violated invariant: destination_chain is not serializable"),
                )
                .add_attribute(
                    "command_batch_id",
                    serde_json::to_string(&command_batch_id)
                        .expect("violated invariant: command_batch_id is not serializable"),
                )
                .add_attribute(
                    "multisig_session_id",
                    serde_json::to_string(&multisig_session_id)
                        .expect("violated invariant: multisig_session_id is not serializable"),
                )
                .add_attribute(
                    "message_ids",
                    serde_json::to_string(&msg_ids)
                        .expect("violated invariant: message_ids is not serializable"),
                ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::BatchId;
    use serde_json::to_string;

    #[test]
    fn proof_under_construction_is_serializable() {
        let msg_ids = vec![
            CrossChainId {
                chain: "ethereum".parse().unwrap(),
                id: "some_id".try_into().unwrap(),
            },
            CrossChainId {
                chain: "fantom".parse().unwrap(),
                id: "some_other_id".try_into().unwrap(),
            },
        ];

        let event = Event::ProofUnderConstruction {
            destination_chain: "avalanche".parse().unwrap(),
            command_batch_id: BatchId::new(&msg_ids, None),
            multisig_session_id: Uint64::new(2),
            msg_ids,
        };

        assert!(to_string(&cosmwasm_std::Event::from(event)).is_ok());
    }
}
