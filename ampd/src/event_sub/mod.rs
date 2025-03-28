use std::time::Duration;

use error_stack::{Report, Result};
use events::Event;
use futures::{future, StreamExt, TryStreamExt};
use mockall::automock;
use report::LoggableError;
use tendermint::block;
use thiserror::Error;
use tokio::select;
use tokio::sync::broadcast::{self, Sender};
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::Stream;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use valuable::Valuable;

use crate::asyncutil::future::RetryPolicy;
use crate::tm_client::TmClient;

pub mod stream;

const POLL_INTERVAL: Duration = Duration::from_secs(5);
const BLOCK_PROCESSING_RETRY_POLICY: RetryPolicy = RetryPolicy::RepeatConstant {
    sleep: Duration::from_secs(3),
    max_attempts: 3,
};

#[derive(Error, Debug, Clone)]
pub enum Error {
    #[error("failed querying the latest block")]
    LatestBlockQuery,
    #[error("failed querying the block results for block {block}")]
    BlockResultsQuery { block: block::Height },
    #[error("failed decoding event in block {block}")]
    EventDecoding { block: block::Height },
    #[error("failed receiving event from broadcast stream")]
    BroadcastStreamRecv(#[from] BroadcastStreamRecvError),
}

#[automock]
pub trait EventSub {
    fn subscribe(&self) -> impl Stream<Item = Result<Event, Error>> + Send + 'static;
}

pub struct EventSubscriber {
    tx: Sender<std::result::Result<Event, Error>>,
}

impl EventSub for EventSubscriber {
    fn subscribe(&self) -> impl Stream<Item = Result<Event, Error>> + 'static {
        BroadcastStream::new(self.tx.subscribe())
            .map(|event| match event {
                Ok(Ok(event)) => Ok(event),
                Ok(Err(err)) => Err(err),
                Err(err) => Err(err.into()),
            })
            .map_err(Report::from)
    }
}

pub struct EventPublisher<T: TmClient + Sync> {
    tm_client: T,
    poll_interval: Duration,
    tx: Sender<std::result::Result<Event, Error>>,
}

impl<T: TmClient + Sync> EventPublisher<T> {
    pub fn new(client: T, capacity: usize) -> (Self, EventSubscriber) {
        let (tx, _) = broadcast::channel(capacity);
        let publisher = EventPublisher {
            tm_client: client,
            poll_interval: POLL_INTERVAL,
            tx: tx.clone(),
        };
        let subscriber = EventSubscriber { tx };

        (publisher, subscriber)
    }

    pub async fn run(self, token: CancellationToken) -> Result<(), Error> {
        let block_stream = stream::blocks(&self.tm_client, self.poll_interval, token.child_token())
            .await?
            .filter(|_| future::ready(self.has_subscriber())); // skip processing blocks when no subscriber exists
        let mut event_stream =
            stream::events(&self.tm_client, block_stream, BLOCK_PROCESSING_RETRY_POLICY);

        loop {
            select! {
                event = event_stream.next() => match event {
                    Some(event) => {
                        let event = event
                            .inspect_err(|err| {
                                error!(err = LoggableError::from(err).as_value(), "failed to subscribe to events");
                            })
                            .map_err(|err| err.current_context().clone());
                        let _ = self.tx.send(event);
                    },
                    None => {
                        break;
                    }
                },
                _ = token.cancelled() => {
                    break;
                },
            }
        }

        info!("exiting event sub");

        Ok(())
    }

    fn has_subscriber(&self) -> bool {
        self.tx.receiver_count() > 0
    }
}

#[cfg(test)]
mod tests {
    use std::sync;

    use axelar_wasm_std::assert_err_contains;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use error_stack::report;
    use events::Event;
    use futures::stream::StreamExt;
    use random_string::generate;
    use tendermint::abci;
    use tendermint::block;
    use tokio_util::sync::CancellationToken;

    use crate::event_sub::{Error, EventPublisher, EventSub};
    use crate::tm_client::{self, MockTmClient};

    #[tokio::test(flavor = "multi_thread")]
    async fn should_skip_processing_blocks_when_no_subscriber_exists() {
        let block: tendermint::Block =
            serde_json::from_str(include_str!("../tests/axelar_block.json")).unwrap();
        let mut height = block.header().height;

        let mut tm_client = MockTmClient::new();
        let call_count = sync::Arc::new(sync::RwLock::new(0));
        let inner_call_count = call_count.clone();
        tm_client.expect_latest_block().returning(move || {
            *inner_call_count.write().unwrap() += 1;

            let mut block = block.clone();
            height = height.increment();
            block.header.height = height;

            Ok(tm_client::BlockResponse {
                block_id: Default::default(),
                block,
            })
        });
        tm_client.expect_block_results().never();

        let token = CancellationToken::new();
        let (event_publisher, _subscriber) = EventPublisher::new(tm_client, 100);
        let handle = tokio::spawn(event_publisher.run(token.child_token()));

        while *call_count.read().unwrap() < 10 {}

        token.cancel();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_stream_events_and_errors() {
        let block: tendermint::Block =
            serde_json::from_str(include_str!("../tests/axelar_block.json")).unwrap();
        let initial_height = block.header().height;

        let mut tm_client = MockTmClient::new();
        let mut call_count = 0;
        let mut height = initial_height;
        tm_client.expect_latest_block().returning(move || {
            call_count += 1;

            match call_count {
                1 => Ok(tm_client::BlockResponse {
                    block_id: Default::default(),
                    block: block.clone(),
                }),
                2 => Err(report!(tendermint_rpc::Error::server(
                    "server error".to_string()
                ))),
                _ => {
                    let mut block = block.clone();
                    height = height.increment();
                    block.header.height = height;

                    Ok(tm_client::BlockResponse {
                        block_id: Default::default(),
                        block,
                    })
                }
            }
        });
        tm_client.expect_block_results().returning(move |height| {
            if height == initial_height {
                Ok(block_results_response(
                    height,
                    vec![random_event()],
                    vec![random_event()],
                    vec![random_event()],
                ))
            } else if height == initial_height.increment() {
                Err(report!(tendermint_rpc::Error::server(
                    "server error".to_string()
                )))
            } else {
                Ok(block_results_response(height, vec![], vec![], vec![]))
            }
        });

        let token = CancellationToken::new();
        let (event_publisher, subscriber) = EventPublisher::new(tm_client, 100);
        let mut stream = subscriber.subscribe();
        let handle = tokio::spawn(event_publisher.run(token.child_token()));

        assert!(matches!(
            stream.next().await.unwrap(),
            Ok(Event::BlockBegin(_))
        ));
        assert!(matches!(
            stream.next().await.unwrap(),
            Ok(Event::Abci { .. })
        ));
        assert!(matches!(
            stream.next().await.unwrap(),
            Ok(Event::Abci { .. })
        ));
        assert!(matches!(
            stream.next().await.unwrap(),
            Ok(Event::Abci { .. })
        ));
        assert!(matches!(
            stream.next().await.unwrap(),
            Ok(Event::BlockEnd(_))
        ));
        assert_err_contains!(stream.next().await.unwrap(), Error, Error::LatestBlockQuery);
        assert_err_contains!(
            stream.next().await.unwrap(),
            Error,
            Error::BlockResultsQuery { .. }
        );

        token.cancel();
        handle.await.unwrap().unwrap();
    }

    pub fn random_event() -> abci::Event {
        let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        abci::Event::new(
            generate(10, charset),
            vec![abci::EventAttribute {
                key: STANDARD.encode(generate(10, charset)),
                value: STANDARD.encode(generate(10, charset)),
                index: false,
            }],
        )
    }

    pub fn block_results_response(
        height: block::Height,
        begin_block_events: Vec<abci::Event>,
        end_block_events: Vec<abci::Event>,
        txs_events: Vec<abci::Event>,
    ) -> tm_client::BlockResultsResponse {
        tm_client::BlockResultsResponse {
            height,
            begin_block_events: Some(begin_block_events),
            end_block_events: Some(end_block_events),
            consensus_param_updates: None,
            txs_results: Some(
                txs_events
                    .into_iter()
                    .map(|event| abci::types::ExecTxResult {
                        events: vec![event],
                        ..Default::default()
                    })
                    .collect(),
            ),
            validator_updates: vec![],
            app_hash: Default::default(),
            finalize_block_events: vec![],
        }
    }
}
