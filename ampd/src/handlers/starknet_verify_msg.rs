use std::convert::TryInto;

use async_trait::async_trait;
use axelar_wasm_std::msg_id::FieldElementAndEventIndex;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use error_stack::ResultExt;
use events::try_from;
use events::Error::EventTypeMismatch;
use futures::future::join_all;
use itertools::Itertools;
use router_api::ChainName;
use serde::Deserialize;
use starknet_checked_felt::CheckedFelt;
use tokio::sync::watch::Receiver;
use tracing::info;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::handlers::errors::Error::DeserializeEvent;
use crate::handlers::record_metrics::*;
use crate::monitoring;
use crate::starknet::json_rpc::StarknetClient;
use crate::starknet::verifier::verify_msg;
use crate::types::{Hash, TMAddress};

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct Message {
    pub message_id: FieldElementAndEventIndex,
    pub destination_address: String,
    pub destination_chain: ChainName,
    pub source_address: CheckedFelt,
    pub payload_hash: Hash,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-messages_poll_started")]
struct PollStartedEvent {
    #[serde(rename = "_contract_address")]
    contract_address: TMAddress,
    poll_id: PollId,
    source_gateway_address: String,
    expires_at: u64,
    messages: Vec<Message>,
    participants: Vec<TMAddress>,
}

#[derive(Debug)]
pub struct Handler<C>
where
    C: StarknetClient,
{
    verifier: TMAddress,
    voting_verifier: TMAddress,
    rpc_client: C,
    latest_block_height: Receiver<u64>,
    monitoring_client: monitoring::Client,
}

impl<C> Handler<C>
where
    C: StarknetClient + Send + Sync,
{
    pub fn new(
        verifier: TMAddress,
        voting_verifier: TMAddress,
        rpc_client: C,
        latest_block_height: Receiver<u64>,
        monitoring_client: monitoring::Client,
    ) -> Self {
        Self {
            verifier,
            voting_verifier,
            rpc_client,
            latest_block_height,
            monitoring_client,
        }
    }

    fn vote_msg(&self, poll_id: PollId, votes: Vec<Vote>) -> MsgExecuteContract {
        MsgExecuteContract {
            sender: self.verifier.as_ref().clone(),
            contract: self.voting_verifier.as_ref().clone(),
            msg: serde_json::to_vec(&ExecuteMsg::Vote { poll_id, votes })
                .expect("vote msg should serialize"),
            funds: vec![],
        }
    }
}

#[async_trait]
impl<V> EventHandler for Handler<V>
where
    V: StarknetClient + Send + Sync,
{
    type Err = Error;

    async fn handle(&self, event: &events::Event) -> Result<Vec<Any>> {
        let PollStartedEvent {
            poll_id,
            source_gateway_address,
            messages,
            participants,
            expires_at,
            contract_address,
            ..
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(vec![]);
            }
            event => event.change_context(DeserializeEvent)?,
        };

        if self.voting_verifier != contract_address {
            return Ok(vec![]);
        }

        if !participants.contains(&self.verifier) {
            return Ok(vec![]);
        }

        let latest_block_height = *self.latest_block_height.borrow();
        if latest_block_height >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");
            return Ok(vec![]);
        }

        let handler_chain_name = "starknet";

        let votes = join_all(
            messages
                .iter()
                .unique_by(|msg| msg.message_id.to_string())
                .map(|msg| async {
                    let vote = match self
                        .rpc_client
                        .get_event_by_message_id_contract_call(msg.message_id.clone())
                        .await
                    {
                        Some(event) => verify_msg(&event, msg, &source_gateway_address),
                        None => Vote::NotFound,
                    };

                    record_vote_verification_metric(
                        &self.monitoring_client,
                        &vote,
                        handler_chain_name,
                    );

                    vote
                }),
        )
        .await;

        Ok(vec![self
            .vote_msg(poll_id, votes)
            .into_any()
            .expect("vote msg should serialize")])
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::str::FromStr;

    use axelar_wasm_std::voting::Vote;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use ethers_core::types::H256;
    use events::Event;
    use mockall::predicate::eq;
    use starknet_core::types::Felt;
    use tendermint::abci;
    use tokio::sync::watch;
    use tokio::test as async_test;
    use voting_verifier::events::{PollMetadata, PollStarted, TxEventConfirmation};

    use super::*;
    use crate::monitoring::metrics::Msg as MetricsMsg;
    use crate::monitoring::test_utils::create_test_monitoring_client;
    use crate::starknet::json_rpc::MockStarknetClient;
    use crate::types::starknet::events::contract_call::ContractCallEvent;
    use crate::PREFIX;

    #[async_test]
    async fn should_correctly_validate_two_messages_within_the_same_tx() {
        // Setup the context
        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let (_, rx) = watch::channel(expiration - 1);

        // Prepare the rpc client, which fetches the event and the vote broadcaster
        let mut rpc_client = MockStarknetClient::new();
        rpc_client
            .expect_get_event_by_message_id_contract_call()
            .returning(|_| {
                Some(ContractCallEvent {
                    from_contract_addr: String::from("source-gw-addr"),
                    destination_address: String::from("destination-address"),
                    destination_chain: "ethereum".parse().unwrap(),
                    source_address: Felt::ONE,
                    payload_hash: H256::from_slice(&[
                        28u8, 138, 255, 149, 6, 133, 194, 237, 75, 195, 23, 79, 52, 114, 40, 123,
                        86, 217, 81, 123, 156, 148, 129, 39, 49, 154, 9, 167, 163, 109, 234, 200,
                    ]),
                })
            })
            .returning(|_| {
                Some(ContractCallEvent {
                    from_contract_addr: String::from("source-gw-addr"),
                    destination_address: String::from("destination-address-1"),
                    destination_chain: "ethereum-1".parse().unwrap(),
                    source_address: Felt::TWO,
                    payload_hash: H256::from_slice(&[
                        28u8, 138, 255, 149, 6, 133, 194, 237, 75, 195, 23, 79, 52, 114, 40, 123,
                        86, 217, 81, 123, 156, 148, 129, 39, 49, 154, 9, 167, 163, 109, 234, 200,
                    ]),
                })
            });

        let event: Event = get_event(
            get_two_poll_started_events_within_the_same_tx(
                participants(5, Some(verifier.clone())),
                100_u64,
            ),
            &voting_verifier,
        );

        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();

        let handler =
            super::Handler::new(verifier, voting_verifier, rpc_client, rx, monitoring_client);
        let result = handler.handle(&event).await.unwrap();

        assert_eq!(result.len(), 1);
        assert!(MsgExecuteContract::from_any(result.first().unwrap()).is_ok());
    }

    #[async_test]
    async fn should_correctly_validate_messages() {
        // Setup the context
        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let (_, rx) = watch::channel(expiration - 1);

        // Prepare the rpc client, which fetches the event and the vote broadcaster
        let mut rpc_client = MockStarknetClient::new();
        rpc_client
            .expect_get_event_by_message_id_contract_call()
            .returning(|_| {
                Some(ContractCallEvent {
                    from_contract_addr: String::from("source-gw-addr"),
                    destination_address: String::from("destination-address"),
                    destination_chain: "ethereum".parse().unwrap(),
                    source_address: Felt::ONE,
                    payload_hash: H256::from_slice(&[
                        28u8, 138, 255, 149, 6, 133, 194, 237, 75, 195, 23, 79, 52, 114, 40, 123,
                        86, 217, 81, 123, 156, 148, 129, 39, 49, 154, 9, 167, 163, 109, 234, 200,
                    ]),
                })
            });

        let event: Event = get_event(
            get_poll_started_event_with_two_msgs(participants(5, Some(verifier.clone())), 100_u64),
            &voting_verifier,
        );

        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();

        let handler =
            super::Handler::new(verifier, voting_verifier, rpc_client, rx, monitoring_client);
        let result = handler.handle(&event).await.unwrap();

        assert_eq!(result.len(), 1);
        assert!(MsgExecuteContract::from_any(result.first().unwrap()).is_ok());
    }

    #[async_test]
    async fn should_send_correct_vote_messages() {
        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let (_, rx) = watch::channel(expiration - 1);

        let mut rpc_client = MockStarknetClient::new();
        rpc_client
            .expect_get_event_by_message_id_contract_call()
            .returning(|_| None);

        let event: Event = get_event(
            get_poll_started_event_with_two_msgs(participants(5, Some(verifier.clone())), 100_u64),
            &voting_verifier,
        );

        let (monitoring_client, mut receiver) = create_test_monitoring_client();

        let handler =
            super::Handler::new(verifier, voting_verifier, rpc_client, rx, monitoring_client);
        let _ = handler.handle(&event).await.unwrap();

        for _ in 0..2 {
            let msg = receiver.recv().await.unwrap();
            assert_eq!(
                msg,
                MetricsMsg::VoteVerification {
                    vote_status: Vote::NotFound,
                    chain_name: "starknet".to_string(),
                }
            );
        }

        assert!(receiver.try_recv().is_err());
    }

    #[async_test]
    async fn should_skip_duplicate_messages() {
        // Setup the context
        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let (_, rx) = watch::channel(expiration - 1);

        // Prepare the rpc client, which fetches the event and the vote broadcaster
        let mut rpc_client = MockStarknetClient::new();
        rpc_client
            .expect_get_event_by_message_id_contract_call()
            .once()
            .with(eq(FieldElementAndEventIndex {
                tx_hash: CheckedFelt::from_str(
                    "0x045410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439f",
                )
                .unwrap(),
                event_index: 1,
            }))
            .returning(|_| {
                Some(ContractCallEvent {
                    from_contract_addr: String::from("source-gw-addr"),
                    destination_address: String::from("destination-address"),
                    destination_chain: "ethereum".parse().unwrap(),
                    source_address: Felt::ONE,
                    payload_hash: H256::from_slice(&[
                        28u8, 138, 255, 149, 6, 133, 194, 237, 75, 195, 23, 79, 52, 114, 40, 123,
                        86, 217, 81, 123, 156, 148, 129, 39, 49, 154, 9, 167, 163, 109, 234, 200,
                    ]),
                })
            });

        let event: Event = get_event(
            get_poll_started_event_with_duplicate_msgs(
                participants(5, Some(verifier.clone())),
                100,
            ),
            &voting_verifier,
        );

        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();

        let handler =
            super::Handler::new(verifier, voting_verifier, rpc_client, rx, monitoring_client);
        let result = handler.handle(&event).await.unwrap();

        assert_eq!(result.len(), 1);
        assert!(MsgExecuteContract::from_any(result.first().unwrap()).is_ok());
    }

    #[async_test]
    async fn should_skip_wrong_verifier_address() {
        // Setup the context
        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let (_, rx) = watch::channel(expiration - 1);

        // Prepare the rpc client, which fetches the event and the vote broadcaster
        let mut rpc_client = MockStarknetClient::new();
        rpc_client
            .expect_get_event_by_message_id_contract_call()
            .times(0);

        let event: Event = get_event(
            get_poll_started_event_with_duplicate_msgs(
                participants(5, Some(verifier.clone())),
                100,
            ),
            &TMAddress::random(PREFIX), // some other random address
        );

        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();

        let handler =
            super::Handler::new(verifier, voting_verifier, rpc_client, rx, monitoring_client);

        let result = handler.handle(&event).await.unwrap();
        assert_eq!(result, vec![]);
    }

    #[async_test]
    async fn should_skip_non_participating_verifier() {
        // Setup the context
        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let (_, rx) = watch::channel(expiration - 1);

        // Prepare the rpc client, which fetches the event and the vote broadcaster
        let mut rpc_client = MockStarknetClient::new();
        rpc_client
            .expect_get_event_by_message_id_contract_call()
            .times(0);

        let event: Event = get_event(
            // woker is not in participat set
            get_poll_started_event_with_duplicate_msgs(participants(5, None), 100),
            &voting_verifier,
        );

        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();

        let handler =
            super::Handler::new(verifier, voting_verifier, rpc_client, rx, monitoring_client);

        let result = handler.handle(&event).await.unwrap();
        assert_eq!(result, vec![]);
    }

    #[async_test]
    async fn should_skip_expired_poll_event() {
        // Setup the context
        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let (_, rx) = watch::channel(expiration); // expired!

        // Prepare the rpc client, which fetches the event and the vote broadcaster
        let mut rpc_client = MockStarknetClient::new();
        rpc_client
            .expect_get_event_by_message_id_contract_call()
            .times(0);

        let event: Event = get_event(
            get_poll_started_event_with_duplicate_msgs(
                participants(5, Some(verifier.clone())),
                100,
            ),
            &voting_verifier,
        );

        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();

        let handler =
            super::Handler::new(verifier, voting_verifier, rpc_client, rx, monitoring_client);

        let result = handler.handle(&event).await.unwrap();
        assert_eq!(result, vec![]);
    }

    fn participants(n: u8, verifier: Option<TMAddress>) -> Vec<TMAddress> {
        (0..n)
            .map(|_| TMAddress::random(PREFIX))
            .chain(verifier)
            .collect()
    }

    fn get_event(event: impl Into<cosmwasm_std::Event>, contract_address: &TMAddress) -> Event {
        let mut event: cosmwasm_std::Event = event.into();

        event.ty = format!("wasm-{}", event.ty);
        event = event.add_attribute("_contract_address", contract_address.to_string());

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

    fn get_two_poll_started_events_within_the_same_tx(
        participants: Vec<TMAddress>,
        expires_at: u64,
    ) -> PollStarted {
        PollStarted::Messages {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "starknet".parse().unwrap(),
                source_gateway_address: "source-gw-addr".parse().unwrap(),
                confirmation_height: 15,
                expires_at,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
            },
            messages: vec![
                #[allow(deprecated)] // TODO: Use message_id, on deprecating tx_id and event_index
                TxEventConfirmation {
                    tx_id: "0x035410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439e"
                        .parse()
                        .unwrap(),
                    message_id:
                        "0x035410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439e-0"
                            .parse()
                            .unwrap(),
                    event_index: 0,
                    source_address:
                        "0x0000000000000000000000000000000000000000000000000000000000000001"
                            .parse()
                            .unwrap(),
                    destination_chain: "ethereum".parse().unwrap(),
                    destination_address: "destination-address".parse().unwrap(),
                    payload_hash: H256::from_slice(&[
                        // keccak256("hello")
                        28, 138, 255, 149, 6, 133, 194, 237, 75, 195, 23, 79, 52, 114, 40, 123, 86,
                        217, 81, 123, 156, 148, 129, 39, 49, 154, 9, 167, 163, 109, 234, 200,
                    ])
                    .into(),
                },
                #[allow(deprecated)] // TODO: Use message_id, on deprecating tx_id and event_index
                TxEventConfirmation {
                    tx_id: "0x035410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439e"
                        .parse()
                        .unwrap(),
                    message_id:
                        "0x035410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439e-1"
                            .parse()
                            .unwrap(),
                    event_index: 1,
                    source_address:
                        "0x0000000000000000000000000000000000000000000000000000000000000002"
                            .parse()
                            .unwrap(),
                    destination_chain: "ethereum-1".parse().unwrap(),
                    destination_address: "destination-address-1".parse().unwrap(),
                    payload_hash: H256::from_slice(&[
                        // keccak256("hello")
                        28u8, 138, 255, 149, 6, 133, 194, 237, 75, 195, 23, 79, 52, 114, 40, 123,
                        86, 217, 81, 123, 156, 148, 129, 39, 49, 154, 9, 167, 163, 109, 234, 200,
                    ])
                    .into(),
                },
            ],
        }
    }

    fn get_poll_started_event_with_two_msgs(
        participants: Vec<TMAddress>,
        expires_at: u64,
    ) -> PollStarted {
        PollStarted::Messages {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "starknet".parse().unwrap(),
                source_gateway_address: "source-gw-addr".parse().unwrap(),
                confirmation_height: 15,
                expires_at,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
            },
            messages: vec![
                #[allow(deprecated)] // TODO: Use message_id, on deprecating tx_id and event_index
                TxEventConfirmation {
                    tx_id: "0x035410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439e"
                        .parse()
                        .unwrap(),
                    message_id:
                        "0x035410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439e-0"
                            .parse()
                            .unwrap(),
                    event_index: 0,
                    source_address:
                        "0x0000000000000000000000000000000000000000000000000000000000000001"
                            .parse()
                            .unwrap(),
                    destination_chain: "ethereum".parse().unwrap(),
                    destination_address: "destination-address".parse().unwrap(),
                    payload_hash: H256::from_slice(&[
                        // keccak256("hello")
                        28, 138, 255, 149, 6, 133, 194, 237, 75, 195, 23, 79, 52, 114, 40, 123, 86,
                        217, 81, 123, 156, 148, 129, 39, 49, 154, 9, 167, 163, 109, 234, 200,
                    ])
                    .into(),
                },
                #[allow(deprecated)] // TODO: Use message_id, on deprecating tx_id and event_index
                TxEventConfirmation {
                    tx_id: "0x045410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439f"
                        .parse()
                        .unwrap(),
                    message_id:
                        "0x045410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439f-1"
                            .parse()
                            .unwrap(),
                    event_index: 1,
                    source_address:
                        "0x0000000000000000000000000000000000000000000000000000000000000001"
                            .parse()
                            .unwrap(),
                    destination_chain: "ethereum".parse().unwrap(),
                    destination_address: "destination-address".parse().unwrap(),
                    payload_hash: H256::from_slice(&[
                        // keccak256("hello")
                        28u8, 138, 255, 149, 6, 133, 194, 237, 75, 195, 23, 79, 52, 114, 40, 123,
                        86, 217, 81, 123, 156, 148, 129, 39, 49, 154, 9, 167, 163, 109, 234, 200,
                    ])
                    .into(),
                },
            ],
        }
    }

    fn get_poll_started_event_with_duplicate_msgs(
        participants: Vec<TMAddress>,
        expires_at: u64,
    ) -> PollStarted {
        PollStarted::Messages {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "starknet".parse().unwrap(),
                source_gateway_address: "source-gw-addr".parse().unwrap(),
                confirmation_height: 15,
                expires_at,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
            },
            messages: vec![
                #[allow(deprecated)] // TODO: Use message_id, on deprecating tx_id and event_index
                TxEventConfirmation {
                    tx_id: "0x045410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439f"
                        .parse()
                        .unwrap(),
                    message_id:
                        "0x045410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439f-1"
                            .parse()
                            .unwrap(),
                    event_index: 1,
                    source_address:
                        "0x0000000000000000000000000000000000000000000000000000000000000001"
                            .parse()
                            .unwrap(),
                    destination_chain: "ethereum".parse().unwrap(),
                    destination_address: "destination-address".parse().unwrap(),
                    payload_hash: H256::from_slice(&[
                        // keccak256("hello")
                        28u8, 138, 255, 149, 6, 133, 194, 237, 75, 195, 23, 79, 52, 114, 40, 123,
                        86, 217, 81, 123, 156, 148, 129, 39, 49, 154, 9, 167, 163, 109, 234, 200,
                    ])
                    .into(),
                },
                #[allow(deprecated)] // TODO: Use message_id, on deprecating tx_id and event_index
                TxEventConfirmation {
                    tx_id: "0x045410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439f"
                        .parse()
                        .unwrap(),
                    message_id:
                        "0x045410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439f-1"
                            .parse()
                            .unwrap(),
                    event_index: 1,
                    source_address:
                        "0x0000000000000000000000000000000000000000000000000000000000000001"
                            .parse()
                            .unwrap(),
                    destination_chain: "ethereum".parse().unwrap(),
                    destination_address: "destination-address".parse().unwrap(),
                    payload_hash: H256::from_slice(&[
                        // keccak256("hello")
                        28u8, 138, 255, 149, 6, 133, 194, 237, 75, 195, 23, 79, 52, 114, 40, 123,
                        86, 217, 81, 123, 156, 148, 129, 39, 49, 154, 9, 167, 163, 109, 234, 200,
                    ])
                    .into(),
                },
            ],
        }
    }
}
