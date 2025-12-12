use ampd::evm::finalizer::Finalization;
use ampd::evm::json_rpc::EthereumClient;
use ampd::handlers::evm_verify_event::{
    create_vote_msg, deserialize_event_data, fetch_finalized_tx_receipts, should_skip_poll,
    verify_and_vote_on_events, PollStartedEvent,
};
use ampd::monitoring;
use ampd_handlers::voting::Error;
use ampd_sdk::event::event_handler::{EventHandler, SubscriptionParams};
use ampd_sdk::grpc::client::EventHandlerClient;
use async_trait::async_trait;
use axelar_wasm_std::chain::ChainName;
use cosmrs::tx::Msg;
use cosmrs::{AccountId, Any};
use error_stack::{Result, ResultExt};
use events::{AbciEventTypeFilter, EventType};
use tracing::{info, info_span};
use typed_builder::TypedBuilder;

#[derive(Debug, TypedBuilder)]
pub struct Handler<C>
where
    C: EthereumClient,
{
    pub verifier: AccountId,
    pub event_verifier_contract: AccountId,
    pub chain: ChainName,
    pub finalizer_type: Finalization,
    pub confirmation_height: u64,
    pub rpc_client: C,
    pub monitoring_client: monitoring::Client,
}

#[async_trait]
impl<C> EventHandler for Handler<C>
where
    C: EthereumClient + Send + Sync,
{
    type Err = Error;
    type Event = PollStartedEvent;

    async fn handle<HC: EventHandlerClient + Send + 'static>(
        &self,
        event: PollStartedEvent,
        client: &mut HC,
    ) -> Result<Vec<Any>, Self::Err> {
        let PollStartedEvent {
            events: events_to_verify,
            poll_id,
            source_chain,
            expires_at,
            participants,
        } = event;

        let latest_block_height = client
            .latest_block_height()
            .await
            .change_context(Error::VotingEligibility)?;

        if should_skip_poll(
            &self.chain,
            &source_chain,
            &self.verifier,
            &participants,
            latest_block_height,
            expires_at,
            &poll_id,
        ) {
            return Ok(vec![]);
        }

        let events_data = deserialize_event_data(&events_to_verify);

        let finalized_tx_receipts = fetch_finalized_tx_receipts(
            &self.rpc_client,
            &self.finalizer_type,
            &events_data,
            self.confirmation_height,
        )
        .await
        .change_context(Error::FinalizedTxs)?;

        let poll_id_str: String = poll_id.to_string();
        let source_chain_str: String = source_chain.to_string();

        let votes = info_span!(
            "verify events from an EVM chain",
            poll_id = poll_id_str,
            source_chain = source_chain_str,
            event_count = events_to_verify.len(),
        )
        .in_scope(|| {
            info!("ready to verify events in poll");
            let votes = verify_and_vote_on_events(
                &events_data,
                &finalized_tx_receipts,
                &self.monitoring_client,
                &self.chain,
            );

            info!(
                votes = format!("{:?}", votes),
                "ready to vote for events in poll"
            );

            votes
        });

        Ok(vec![create_vote_msg(
            &self.verifier,
            &self.event_verifier_contract,
            poll_id,
            votes,
        )
        .into_any()
        .expect("vote msg should serialize")])
    }

    fn subscription_params(&self) -> SubscriptionParams {
        SubscriptionParams::new(
            vec![AbciEventTypeFilter {
                event_type: PollStartedEvent::event_type(),
                contract: self.event_verifier_contract.clone(),
                attributes: Default::default(),
            }],
            false,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use ampd::evm::finalizer::Finalization;
    use ampd::evm::json_rpc::MockEthereumClient;
    use ampd::monitoring;
    use ampd::types::TMAddress;
    use ampd_handlers::test_utils::{into_structured_event, participants};
    use ampd_sdk::event::event_handler::EventHandler;
    use ampd_sdk::grpc::client::test_utils::MockHandlerTaskClient;
    use axelar_wasm_std::voting::Vote;
    use axelar_wasm_std::{chain_name, fixed_size};
    use cosmrs::AccountId;
    use error_stack::{Report, Result};
    use ethers_core::types::{Block, H256, U64};
    use ethers_providers::ProviderError;
    use event_verifier::events::Event as EventVerifierEvent;
    use event_verifier_api::evm::{Event as ApiEvent, EvmEvent as ApiEvmEvent};
    use event_verifier_api::{EventData, EventToVerify};
    use events::Error::{DeserializationFailed, EventTypeMismatch};
    use events::Event;
    use tokio::test as async_test;

    use super::{Handler, PollStartedEvent};

    const PREFIX: &str = "axelar";
    const ETHEREUM: &str = "ethereum";

    fn events_poll_started_event(
        participants: Vec<TMAddress>,
        expires_at: u64,
    ) -> EventVerifierEvent {
        events_poll_started_event_with_events(participants, expires_at, sample_events())
    }

    fn events_poll_started_event_with_events(
        participants: Vec<TMAddress>,
        expires_at: u64,
        events: Vec<EventToVerify>,
    ) -> EventVerifierEvent {
        let participants_as_addr: Vec<cosmwasm_std::Addr> = participants
            .into_iter()
            .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
            .collect();

        EventVerifierEvent::EventsPollStarted {
            events,
            poll_id: "100".parse().unwrap(),
            source_chain: chain_name!(ETHEREUM),
            expires_at,
            participants: participants_as_addr,
        }
    }

    fn sample_events() -> Vec<EventToVerify> {
        // build three minimal EVM events
        let mk_evm = |byte: u8| -> ApiEvmEvent {
            let tx_hash = fixed_size::HexBinary::<32>::try_from([byte; 32]).unwrap();
            let topics = vec![fixed_size::HexBinary::<32>::try_from([1u8; 32]).unwrap()];
            let data = cosmwasm_std::HexBinary::from(vec![1, 2, 3, 4]);
            let ev = ApiEvent {
                contract_address: fixed_size::HexBinary::<20>::try_from([byte; 20]).unwrap(),
                event_index: 0,
                topics,
                data,
            };
            ApiEvmEvent {
                transaction_hash: tx_hash,
                transaction_details: None,
                events: vec![ev],
            }
        };

        vec![
            EventToVerify {
                source_chain: chain_name!(ETHEREUM),
                event_data: serde_json::to_string(&EventData::Evm(mk_evm(1))).unwrap(),
            },
            EventToVerify {
                source_chain: chain_name!(ETHEREUM),
                event_data: serde_json::to_string(&EventData::Evm(mk_evm(2))).unwrap(),
            },
            EventToVerify {
                source_chain: chain_name!(ETHEREUM),
                event_data: serde_json::to_string(&EventData::Evm(mk_evm(3))).unwrap(),
            },
        ]
    }

    fn mock_handler_client(latest_block_height: u64) -> MockHandlerTaskClient {
        let mut client = MockHandlerTaskClient::new();
        client
            .expect_latest_block_height()
            .returning(move || Ok(latest_block_height));
        client
    }

    #[test]
    fn should_not_deserialize_incorrect_event() {
        // incorrect event type
        let mut event: Event = into_structured_event(
            events_poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        match event {
            Event::Abci {
                ref mut event_type, ..
            } => {
                *event_type = "incorrect".into();
            }
            _ => panic!("incorrect event type"),
        }
        let event: Result<PollStartedEvent, events::Error> = (&event).try_into();

        assert!(matches!(
            event.unwrap_err().current_context(),
            EventTypeMismatch(_)
        ));

        // invalid field
        let mut event: Event = into_structured_event(
            events_poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        match event {
            Event::Abci {
                ref mut attributes, ..
            } => {
                attributes.insert("poll_id".into(), "{\"invalid\": \"json\"}".into());
            }
            _ => panic!("incorrect event type"),
        }

        let event: Result<PollStartedEvent, events::Error> = (&event).try_into();

        assert!(matches!(
            event.unwrap_err().current_context(),
            DeserializationFailed(_, _)
        ));
    }

    #[test]
    fn evm_verify_event_should_deserialize_correct_event() {
        let event: Event = into_structured_event(
            events_poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        let event: PollStartedEvent = event.try_into().unwrap();

        goldie::assert_debug!(event);
    }

    #[async_test]
    async fn should_skip_expired_poll() {
        let mut rpc_client = MockEthereumClient::new();
        // mock the rpc client as erroring. If the handler successfully ignores the poll, we won't hit this
        rpc_client.expect_finalized_block().returning(|| {
            Err(Report::from(ProviderError::CustomError(
                "failed to get finalized block".to_string(),
            )))
        });

        let event_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event: Event = into_structured_event(
            events_poll_started_event(participants(5, Some(verifier.clone())), expiration),
            &event_verifier_contract,
        );

        let (monitoring_client, _) = monitoring::test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(AccountId::from(verifier))
            .event_verifier_contract(AccountId::from(event_verifier_contract))
            .chain(chain_name!(ETHEREUM))
            .finalizer_type(Finalization::RPCFinalizedBlock)
            .confirmation_height(1)
            .rpc_client(rpc_client)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(expiration - 1);

        // poll is not expired yet, should hit rpc error
        assert!(handler
            .handle(event.clone().try_into().unwrap(), &mut client)
            .await
            .is_err());

        let mut client = mock_handler_client(expiration + 1);

        // poll is expired, should not hit rpc error now
        assert_eq!(
            handler
                .handle(event.try_into().unwrap(), &mut client)
                .await
                .unwrap(),
            vec![]
        );
    }

    #[async_test]
    async fn should_record_verification_vote_metric() {
        let mut rpc_client = MockEthereumClient::new();
        let mut block = Block::<ampd::types::Hash>::default();
        let block_number: U64 = 10.into();
        block.number = Some(block_number);

        rpc_client
            .expect_finalized_block()
            .returning(move || Ok(block.clone()));

        rpc_client
            .expect_transaction_receipt()
            .returning(|_| Ok(None));

        let event_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let event: Event = into_structured_event(
            events_poll_started_event(participants(5, Some(verifier.clone())), 100),
            &event_verifier_contract,
        );
        let (monitoring_client, mut receiver) = monitoring::test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(AccountId::from(verifier))
            .event_verifier_contract(AccountId::from(event_verifier_contract))
            .chain(chain_name!(ETHEREUM))
            .finalizer_type(Finalization::RPCFinalizedBlock)
            .confirmation_height(1)
            .rpc_client(rpc_client)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(0);

        assert!(handler
            .handle(event.try_into().unwrap(), &mut client)
            .await
            .is_ok());

        for _ in 0..3 {
            let metrics = receiver.recv().await.unwrap();

            assert_eq!(
                metrics,
                monitoring::metrics::Msg::VerificationVote {
                    vote_decision: Vote::NotFound,
                    chain_name: chain_name!(ETHEREUM),
                }
            );
        }

        assert!(receiver.try_recv().is_err());
    }

    #[async_test]
    async fn should_vote_not_found_on_malformed_event_data() {
        let mut rpc_client = MockEthereumClient::new();
        let mut block = Block::<ampd::types::Hash>::default();
        let block_number: U64 = 10.into();
        block.number = Some(block_number);

        // mock finalized block so finalizer works
        rpc_client
            .expect_finalized_block()
            .returning(move || Ok(block.clone()));

        // also mock transaction_receipt to return Some with finalized block to ensure that,
        // even if called, it wouldn't cause NotFound by itself
        let dummy_receipt = ethers_core::types::TransactionReceipt {
            transaction_hash: H256::repeat_byte(0x01),
            status: Some(1u64.into()),
            block_number: Some(5u64.into()),
            logs: vec![],
            ..Default::default()
        };
        rpc_client
            .expect_transaction_receipt()
            .returning(move |_| Ok(Some(dummy_receipt.clone())));

        // events array with one entry whose event_data is a malformed JSON string
        let event_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);

        let malformed_events = vec![EventToVerify {
            source_chain: chain_name!(ETHEREUM),
            event_data: "{ this is not valid json".to_string(),
        }];

        let event: Event = into_structured_event(
            events_poll_started_event_with_events(
                participants(1, Some(verifier.clone())),
                100,
                malformed_events,
            ),
            &event_verifier_contract,
        );

        let (monitoring_client, mut receiver) = monitoring::test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(AccountId::from(verifier))
            .event_verifier_contract(AccountId::from(event_verifier_contract))
            .chain(chain_name!(ETHEREUM))
            .finalizer_type(Finalization::RPCFinalizedBlock)
            .confirmation_height(1)
            .rpc_client(rpc_client)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(0);

        assert!(handler
            .handle(event.try_into().unwrap(), &mut client)
            .await
            .is_ok());

        // Expect a single NotFound vote to be recorded
        let metrics = receiver.recv().await.unwrap();
        assert_eq!(
            metrics,
            monitoring::metrics::Msg::VerificationVote {
                vote_decision: Vote::NotFound,
                chain_name: chain_name!(ETHEREUM),
            }
        );

        assert!(receiver.try_recv().is_err());
    }
}
