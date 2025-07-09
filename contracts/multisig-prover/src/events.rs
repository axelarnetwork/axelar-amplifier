use axelar_wasm_std::IntoEvent;
use cosmwasm_std::Uint64;
use router_api::{ChainName, CrossChainId};

use crate::payload::PayloadId;

#[derive(IntoEvent)]
pub enum Event {
    ProofUnderConstruction {
        destination_chain: ChainName,
        payload_id: PayloadId,
        multisig_session_id: Uint64,
        msg_ids: Vec<CrossChainId>,
    },
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

        let event = Event::ProofUnderConstruction {
            destination_chain: "avalanche".parse().unwrap(),
            payload_id: payload.id(),
            multisig_session_id: Uint64::new(2),
            msg_ids: payload.message_ids().unwrap(),
        };
        let event = cosmwasm_std::Event::from(event);

        goldie::assert_json!(event);
    }
}
