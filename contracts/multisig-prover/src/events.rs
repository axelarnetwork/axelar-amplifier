use cosmwasm_std::Event;
use cosmwasm_std::Uint64;
use router_api::{ChainName, CrossChainId};

use crate::payload::PayloadId;

pub struct ProofUnderConstruction {
    pub destination_chain: ChainName,
    pub payload_id: PayloadId,
    pub multisig_session_id: Uint64,
    pub msg_ids: Vec<CrossChainId>,
}

impl From<ProofUnderConstruction> for Event {
    fn from(other: ProofUnderConstruction) -> Self {
        Event::new("proof_under_construction")
            .add_attribute(
                "destination_chain",
                serde_json::to_string(&other.destination_chain)
                    .expect("failed to serialize destination_chain"),
            )
            .add_attribute(
                "payload_id",
                serde_json::to_string(&other.payload_id).expect("failed to serialize payload_id"),
            )
            .add_attribute(
                "multisig_session_id",
                serde_json::to_string(&other.multisig_session_id)
                    .expect("failed to serialize multisig_session_id"),
            )
            .add_attribute(
                "msg_ids",
                serde_json::to_string(&other.msg_ids).expect("failed to serialize msg_ids"),
            )
    }
}
#[cfg(test)]
mod tests {
    use router_api::Message;

    use super::*;
    use crate::Payload;

    #[test]
    fn proof_under_construction_is_serializable() {
        let payload = Payload::Messages(vec![
            Message {
                cc_id: CrossChainId::new("ethereum", "some-id").unwrap(),
                source_address: "0x1234".parse().unwrap(),
                destination_chain: "avalanche".parse().unwrap(),
                destination_address: "0x5678".parse().unwrap(),
                payload_hash: [0; 32],
            },
            Message {
                cc_id: CrossChainId::new("fantom", "some-other-id").unwrap(),
                source_address: "0x1234".parse().unwrap(),
                destination_chain: "avalanche".parse().unwrap(),
                destination_address: "0x5678".parse().unwrap(),
                payload_hash: [0; 32],
            },
        ]);

        let event = ProofUnderConstruction {
            destination_chain: "avalanche".parse().unwrap(),
            payload_id: payload.id(),
            multisig_session_id: Uint64::new(2),
            msg_ids: payload.message_ids().unwrap(),
        };
        let event = cosmwasm_std::Event::from(event);

        goldie::assert_json!(event);
    }
}
