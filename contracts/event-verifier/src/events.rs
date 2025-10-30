use axelar_wasm_std::voting::{PollId, Vote};
use axelar_wasm_std::{IntoEvent, VerificationStatus};
use cosmwasm_std::Addr;
use router_api::ChainName;

#[derive(IntoEvent)]
pub enum Event {
    Instantiated {
        service_name: String,
        service_registry_contract: Addr,
        voting_threshold: axelar_wasm_std::MajorityThreshold,
        block_expiry: u64,
    },
    EventsPollStarted {
        events: Vec<event_verifier_api::EventToVerify>,
        poll_id: PollId,
        source_chain: ChainName,
        expires_at: u64,
        participants: Vec<Addr>,
    },
    Voted {
        poll_id: PollId,
        voter: Addr,
        votes: Vec<Vote>,
    },
    QuorumReached {
        content: event_verifier_api::EventToVerify,
        status: VerificationStatus,
        poll_id: PollId,
    },
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::MockApi;
    use cosmwasm_std::Event as CosmosEvent;

    use super::*;

    #[test]
    fn instantiated_event_doesnt_change() {
        let api = MockApi::default();
        let event: CosmosEvent = Event::Instantiated {
            service_name: "validators".to_string(),
            service_registry_contract: api.addr_make("service-registry"),
            voting_threshold: axelar_wasm_std::MajorityThreshold::try_from(
                axelar_wasm_std::Threshold::try_from((2u64, 3u64)).unwrap(),
            )
            .unwrap(),
            block_expiry: 100u64,
        }
        .into();

        goldie::assert_json!(event);
    }

    #[test]
    fn poll_started_event_doesnt_change() {
        let api = MockApi::default();

        let event_events_poll_started: cosmwasm_std::Event = Event::EventsPollStarted {
            events: vec![
                event_verifier_api::EventToVerify {
                    source_chain: "sourceChain".try_into().unwrap(),
                    event_data: serde_json::to_string(&event_verifier_api::EventData::Evm(
                        event_verifier_api::evm::EvmEvent {
                            transaction_hash:
                                axelar_wasm_std::fixed_size::HexBinary::<32>::try_from(vec![
                                    0u8;
                                    32
                                ])
                                .unwrap(),
                            transaction_details: None,
                            events: vec![event_verifier_api::evm::Event {
                                contract_address:
                                    axelar_wasm_std::fixed_size::HexBinary::<20>::try_from(vec![
                                        0u8;
                                        20
                                    ])
                                    .unwrap(),
                                event_index: 1,
                                topics: vec![{
                                    let mut bytes = vec![0u8; 32];
                                    bytes[0] = 1;
                                    bytes[1] = 2;
                                    bytes[2] = 3;
                                    axelar_wasm_std::fixed_size::HexBinary::<32>::try_from(bytes)
                                        .unwrap()
                                }],
                                data: cosmwasm_std::HexBinary::from(vec![1, 2, 3, 4]),
                            }],
                        },
                    ))
                    .unwrap(),
                },
                event_verifier_api::EventToVerify {
                    source_chain: "sourceChain".try_into().unwrap(),
                    event_data: serde_json::to_string(&event_verifier_api::EventData::Evm(
                        event_verifier_api::evm::EvmEvent {
                            transaction_hash:
                                axelar_wasm_std::fixed_size::HexBinary::<32>::try_from(vec![
                                    0u8;
                                    32
                                ])
                                .unwrap(),
                            transaction_details: None,
                            events: vec![event_verifier_api::evm::Event {
                                contract_address:
                                    axelar_wasm_std::fixed_size::HexBinary::<20>::try_from(vec![
                                        0u8;
                                        20
                                    ])
                                    .unwrap(),
                                event_index: 2,
                                topics: vec![{
                                    let mut bytes = vec![0u8; 32];
                                    bytes[0] = 1;
                                    bytes[1] = 2;
                                    bytes[2] = 3;
                                    axelar_wasm_std::fixed_size::HexBinary::<32>::try_from(bytes)
                                        .unwrap()
                                }],
                                data: cosmwasm_std::HexBinary::from(vec![5, 6, 7, 8]),
                            }],
                        },
                    ))
                    .unwrap(),
                },
            ],
            poll_id: 1.into(),
            source_chain: "sourceChain".try_into().unwrap(),
            expires_at: 1,
            participants: vec![
                api.addr_make("participant1"),
                api.addr_make("participant2"),
                api.addr_make("participant3"),
            ],
        }
        .into();

        goldie::assert_json!(event_events_poll_started);
    }

    #[test]
    fn voted_event_doesnt_change() {
        let api = MockApi::default();
        let event: CosmosEvent = Event::Voted {
            poll_id: 7u64.into(),
            voter: api.addr_make("voter1"),
            votes: vec![Vote::SucceededOnChain, Vote::FailedOnChain],
        }
        .into();

        goldie::assert_json!(event);
    }

    #[test]
    fn quorum_reached_event_doesnt_change() {
        let content = event_verifier_api::EventToVerify {
            source_chain: "sourceChain".try_into().unwrap(),
            event_data: serde_json::to_string(&event_verifier_api::EventData::Evm(
                event_verifier_api::evm::EvmEvent {
                    transaction_hash: axelar_wasm_std::fixed_size::HexBinary::<32>::try_from(
                        vec![0u8; 32],
                    )
                    .unwrap(),
                    transaction_details: None,
                    events: vec![event_verifier_api::evm::Event {
                        contract_address: axelar_wasm_std::fixed_size::HexBinary::<20>::try_from(
                            vec![0u8; 20],
                        )
                        .unwrap(),
                        event_index: 0,
                        topics: vec![],
                        data: cosmwasm_std::HexBinary::from(vec![1, 2, 3, 4]),
                    }],
                },
            ))
            .unwrap(),
        };

        let event: CosmosEvent = Event::QuorumReached {
            content,
            status: VerificationStatus::SucceededOnSourceChain,
            poll_id: 9u64.into(),
        }
        .into();

        goldie::assert_json!(event);
    }
}
