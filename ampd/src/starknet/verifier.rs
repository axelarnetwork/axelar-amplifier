use axelar_wasm_std::voting::Vote;

use super::events::contract_call::ContractCallEvent;
use crate::handlers::starknet_verify_msg::Message;

/// Attempts to fetch the tx provided in `axl_msg.tx_id`.
/// If successful, extracts and parses the ContractCall event
/// and compares it to the message from the relayer (via PollStarted event).
/// Also checks if the source_gateway_address with which
/// the voting verifier has been instantiated is the same address from
/// which the ContractCall event is coming.
pub fn verify_msg(
    starknet_event: &ContractCallEvent,
    msg: &Message,
    source_gateway_address: &str,
) -> Vote {
    if *starknet_event == *msg && starknet_event.from_contract_addr == source_gateway_address {
        Vote::SucceededOnChain
    } else {
        Vote::NotFound
    }
}

impl PartialEq<Message> for ContractCallEvent {
    fn eq(&self, axl_msg: &Message) -> bool {
        axl_msg.source_address == self.source_address
            && axl_msg.destination_chain == self.destination_chain
            && axl_msg.destination_address == self.destination_address
            && axl_msg.payload_hash == self.payload_hash
    }
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::voting::Vote;
    use ethers_core::types::H256;

    use super::verify_msg;
    use crate::handlers::starknet_verify_msg::Message;
    use crate::starknet::events::contract_call::ContractCallEvent;

    // "hello" as payload
    // "hello" as destination address
    // "some_contract_address" as source address
    // "destination_chain" as destination_chain
    fn mock_valid_event() -> ContractCallEvent {
        ContractCallEvent {
            from_contract_addr: String::from(
                "0x035410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439e",
            ),
            destination_address: String::from("destination_address"),
            destination_chain: String::from("destination_chain"),
            source_address: String::from(
                "0x00b3ff441a68610b30fd5e2abbf3a1548eb6ba6f3559f2862bf2dc757e5828ca",
            ),
            payload_hash: H256::from_slice(&[
                28u8, 138, 255, 149, 6, 133, 194, 237, 75, 195, 23, 79, 52, 114, 40, 123, 86, 217,
                81, 123, 156, 148, 129, 39, 49, 154, 9, 167, 163, 109, 234, 200,
            ]),
        }
    }

    fn mock_valid_message() -> Message {
        Message {
            tx_id: "txid".to_owned(),
            event_index: 0,
            destination_address: String::from("destination_address"),
            destination_chain: String::from("destination_chain"),
            source_address: String::from(
                "0x00b3ff441a68610b30fd5e2abbf3a1548eb6ba6f3559f2862bf2dc757e5828ca",
            ),
            payload_hash: H256::from_slice(&[
                28u8, 138, 255, 149, 6, 133, 194, 237, 75, 195, 23, 79, 52, 114, 40, 123, 86, 217,
                81, 123, 156, 148, 129, 39, 49, 154, 9, 167, 163, 109, 234, 200,
            ]),
        }
    }

    #[test]
    fn shoud_fail_different_source_gw() {
        assert_eq!(
            verify_msg(
                &mock_valid_event(),
                &mock_valid_message(),
                &String::from("different"),
            ),
            Vote::NotFound
        )
    }

    #[test]
    fn shoud_fail_different_event_fields() {
        let msg = mock_valid_message();
        let source_gw_address =
            String::from("0x035410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439e");

        let mut event = mock_valid_event();
        event.destination_address = String::from("different");
        assert_eq!(verify_msg(&event, &msg, &source_gw_address), Vote::NotFound);

        let mut event = { mock_valid_event() };
        event.destination_chain = String::from("different");
        assert_eq!(verify_msg(&event, &msg, &source_gw_address), Vote::NotFound);

        let mut event = { mock_valid_event() };
        event.source_address = String::from("different");
        assert_eq!(verify_msg(&event, &msg, &source_gw_address), Vote::NotFound);

        let mut event = { mock_valid_event() };
        event.payload_hash = H256::from_slice(&[
            28u8, 138, 255, 149, 6, 133, 194, 237, 75, 195, 23, 79, 52, 114, 40, 123, 86, 217, 81,
            123, 156, 148, 129, 39, 49, 154, 9, 167, 163, 109, 234,
            1, // last byte is different
        ]);
        assert_eq!(verify_msg(&event, &msg, &source_gw_address), Vote::NotFound);
    }

    #[test]
    fn shoud_fail_different_msg_fields() {
        let event = mock_valid_event();
        let source_gw_address =
            String::from("0x035410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439e");

        let mut msg = mock_valid_message();
        msg.destination_address = String::from("different");
        assert_eq!(verify_msg(&event, &msg, &source_gw_address), Vote::NotFound);

        let mut msg = { mock_valid_message() };
        msg.destination_chain = String::from("different");
        assert_eq!(verify_msg(&event, &msg, &source_gw_address), Vote::NotFound);

        let mut msg = { mock_valid_message() };
        msg.source_address = String::from("different");
        assert_eq!(verify_msg(&event, &msg, &source_gw_address), Vote::NotFound);

        let mut msg = { mock_valid_message() };
        msg.payload_hash = H256::from_slice(&[
            28u8, 138, 255, 149, 6, 133, 194, 237, 75, 195, 23, 79, 52, 114, 40, 123, 86, 217, 81,
            123, 156, 148, 129, 39, 49, 154, 9, 167, 163, 109, 234,
            1, // last byte is different
        ]);
        assert_eq!(verify_msg(&event, &msg, &source_gw_address), Vote::NotFound);
    }

    #[test]
    fn shoud_verify_event() {
        assert_eq!(
            verify_msg(
                &mock_valid_event(),
                &mock_valid_message(),
                &String::from("0x035410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439e"),
            ),
            Vote::SucceededOnChain
        )
    }
}
