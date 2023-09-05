use error_stack::ResultExt;
use serde::Deserialize;

use axelar_wasm_std::voting::PollID;
use events_derive::try_from;

use crate::types::{EVMAddress, Hash, TMAddress, U256};

#[derive(Deserialize, Debug)]
pub struct Operators {
    pub weights: Vec<(EVMAddress, U256)>,
    pub threshold: U256,
}

#[derive(Deserialize, Debug)]
pub struct WorkerSetConfirmation {
    pub tx_id: Hash,
    pub log_index: u64,
    pub operators: Operators,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-worker_set_poll_started")]
#[allow(dead_code)]
struct PollStartedEvent {
    #[serde(rename = "_contract_address")]
    contract_address: TMAddress,
    worker_set: WorkerSetConfirmation,
    poll_id: PollID,
    source_chain: connection_router::types::ChainName,
    source_gateway_address: EVMAddress,
    confirmation_height: u64,
    expires_at: u64,
    participants: Vec<TMAddress>,
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use tendermint::abci;

    use axelar_wasm_std::operators::Operators;
    use cosmwasm_std::HexBinary;
    use events::Event;
    use voting_verifier::events::{PollMetadata, PollStarted, WorkerSetConfirmation};

    use crate::{
        handlers::evm_verify_worker_set::PollStartedEvent,
        types::{EVMAddress, Hash},
    };

    fn get_poll_started_event() -> Event {
        let poll_started = PollStarted::WorkerSet {
            worker_set: WorkerSetConfirmation {
                tx_id: format!("0x{:x}", Hash::random()),
                log_index: 100,
                operators: Operators {
                    threshold: 40u64.into(),
                    weights: vec![
                        (
                            HexBinary::from(EVMAddress::random().as_bytes()),
                            10u64.into(),
                        ),
                        (
                            HexBinary::from(EVMAddress::random().as_bytes()),
                            20u64.into(),
                        ),
                        (
                            HexBinary::from(EVMAddress::random().as_bytes()),
                            30u64.into(),
                        ),
                    ],
                },
            },
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "ethereum".parse().unwrap(),
                source_gateway_address: "0x4f4495243837681061c4743b74eedf548d5686a5".into(),
                confirmation_height: 15,
                expires_at: 100,
                participants: vec![
                    cosmwasm_std::Addr::unchecked(
                        "axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7",
                    ),
                    cosmwasm_std::Addr::unchecked(
                        "axelarvaloper1tee73c83k2vqky9gt59jd3ztwxhqjm27l588q6",
                    ),
                    cosmwasm_std::Addr::unchecked(
                        "axelarvaloper1ds9z59d9szmxlzt6f8f6l6sgaenxdyd6095gcg",
                    ),
                ],
            },
        };

        let mut event: cosmwasm_std::Event = poll_started.into();
        event.ty = format!("wasm-{}", event.ty);
        event = event.add_attribute(
            "_contract_address",
            "axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7",
        );

        abci::Event::new(
            event.ty,
            event
                .attributes
                .into_iter()
                .map(|cosmwasm_std::Attribute { key, value }| {
                    (STANDARD.encode(key), STANDARD.encode(value))
                }),
        )
        .try_into()
        .unwrap()
    }

    #[test]
    fn should_deserialize_correct_event() {
        let event: Result<PollStartedEvent, _> = (&get_poll_started_event()).try_into();

        assert!(event.is_ok());
    }
}
