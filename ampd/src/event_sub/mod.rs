use std::time::Duration;

use error_stack::{Report, Result};
use events::Event;
use futures::{StreamExt, TryStreamExt};
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

use crate::tm_client::TmClient;

mod event_stream;

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
            poll_interval: Duration::new(5, 0),
            tx: tx.clone(),
        };
        let subscriber = EventSubscriber { tx };

        (publisher, subscriber)
    }

    pub async fn run(self, token: CancellationToken) -> Result<(), Error> {
        let mut event_stream =
            event_stream::event_stream(&self.tm_client, self.poll_interval, 10000, || {
                self.tx.receiver_count() == 0
            })
            .await?;

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
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;
    use std::time::Duration;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use events::Event;
    use futures::stream::StreamExt;
    use mockall::predicate::eq;
    use rand::Rng;
    use random_string::generate;
    use tendermint::{abci, AppHash};
    use tokio::sync::{mpsc, oneshot};
    use tokio::test;
    use tokio_util::sync::CancellationToken;

    use crate::event_sub::{EventPublisher, EventSub};
    use crate::tm_client;

    #[test]
    async fn should_start_from_the_latest_block() {
        let block: tendermint::Block =
            serde_json::from_str(include_str!("../tests/axelar_block.json")).unwrap();
        let height = block.header.height;

        let mut mock_client = tm_client::MockTmClient::new();
        mock_client
            .expect_latest_block()
            .times(2)
            .returning(move || {
                Ok(tm_client::BlockResponse {
                    block_id: Default::default(),
                    block: block.clone(),
                })
            });
        mock_client
            .expect_block_results()
            .once()
            .returning(|height| {
                Ok(tm_client::BlockResultsResponse {
                    height,
                    begin_block_events: None,
                    end_block_events: None,
                    consensus_param_updates: None,
                    txs_results: None,
                    validator_updates: vec![],
                    app_hash: AppHash::default(),
                    finalize_block_events: vec![],
                })
            });

        let token = CancellationToken::new();
        let (event_publisher, event_subcriber) = EventPublisher::new(mock_client, 10);
        let mut stream = event_subcriber.subscribe();

        let child_token = token.child_token();
        let handle = tokio::spawn(async move { event_publisher.run(child_token).await });

        let event = stream.next().await;
        assert_eq!(event.unwrap().unwrap(), Event::BlockBegin(height));

        token.cancel();

        assert!(handle.await.is_ok());
    }

    #[test]
    async fn should_skip_processing_blocks_when_no_subscriber_exists() {
        let latest_block: tendermint::Block =
            serde_json::from_str(include_str!("../tests/axelar_block.json")).unwrap();
        let latest_block_height = latest_block.header.height;

        let (sub_tx, mut sub_rx) = oneshot::channel::<()>();
        let (pub_tx, mut pub_rx) = mpsc::channel::<i32>(100);

        let mut mock_client = tm_client::MockTmClient::new();
        let mut call_count = 0;
        mock_client.expect_latest_block().returning(move || {
            call_count += 1;
            let _ = pub_tx.try_send(call_count);

            let mut block = latest_block.clone();
            if sub_rx.try_recv().is_ok() {
                block.header.height = block.header.height.increment();
            }

            Ok(tm_client::BlockResponse {
                block_id: Default::default(),
                block,
            })
        });
        let latest_block_height = latest_block_height.increment();
        mock_client
            .expect_block_results()
            .with(eq(latest_block_height))
            .return_once(|height| {
                Ok(tm_client::BlockResultsResponse {
                    height,
                    begin_block_events: None,
                    end_block_events: None,
                    consensus_param_updates: None,
                    txs_results: None,
                    validator_updates: vec![],
                    app_hash: AppHash::default(),
                    finalize_block_events: vec![],
                })
            });

        let token = CancellationToken::new();
        let (mut event_publisher, event_subcriber) = EventPublisher::new(mock_client, 100);
        event_publisher.poll_interval = Duration::from_millis(500);
        let handle = tokio::spawn(event_publisher.run(token.child_token()));

        while let Some(call_count) = pub_rx.recv().await {
            if call_count >= 2 {
                break;
            }
        }
        let mut stream = event_subcriber.subscribe();
        sub_tx.send(()).unwrap();
        assert_eq!(
            stream.next().await.unwrap().unwrap(),
            Event::BlockBegin(latest_block_height)
        );
        assert_eq!(
            stream.next().await.unwrap().unwrap(),
            Event::BlockEnd(latest_block_height)
        );

        token.cancel();
        handle.await.unwrap().unwrap();
    }

    #[test]
    async fn stream_should_work() {
        let block_count = 10;
        let block: tendermint::Block =
            serde_json::from_str(include_str!("../tests/axelar_block.json")).unwrap();
        let block_height = block.header.height;
        let mut rng = rand::thread_rng();
        let block_results = tm_client::BlockResultsResponse {
            height: block_height,
            begin_block_events: vec![0; rng.gen_range(0..20)]
                .into_iter()
                .map(|_| Some(random_event()))
                .collect(),
            end_block_events: vec![0; rng.gen_range(0..20)]
                .into_iter()
                .map(|_| Some(random_event()))
                .collect(),
            consensus_param_updates: None,
            txs_results: Some(
                vec![0; rng.gen_range(0..20)]
                    .into_iter()
                    .map(|_| abci::types::ExecTxResult {
                        events: vec![0; rng.gen_range(0..20)]
                            .into_iter()
                            .map(|_| random_event())
                            .collect(),
                        ..Default::default()
                    })
                    .collect(),
            ),
            validator_updates: vec![],
            app_hash: AppHash::default(),
            finalize_block_events: vec![],
        };
        let begin_block_events_count = block_results.begin_block_events.iter().flatten().count();
        let tx_events_count: usize = block_results
            .txs_results
            .iter()
            .flatten()
            .map(|tx| tx.events.len())
            .sum();
        let end_block_events = block_results.end_block_events.iter().flatten().count();
        let event_count_per_block =
            begin_block_events_count + tx_events_count + end_block_events + 2;

        let mut mock_client = tm_client::MockTmClient::new();
        let mut latest_block_call_count = 0;
        mock_client
            .expect_latest_block()
            .times(block_count + 1)
            .returning(move || match latest_block_call_count {
                0 => {
                    latest_block_call_count += 1;
                    Ok(tm_client::BlockResponse {
                        block_id: Default::default(),
                        block: block.clone(),
                    })
                }
                _ => {
                    let mut block = block.clone();
                    block.header.height = (block_height.value() + latest_block_call_count - 1)
                        .try_into()
                        .unwrap();

                    latest_block_call_count += 1;
                    Ok(tm_client::BlockResponse {
                        block_id: Default::default(),
                        block,
                    })
                }
            });
        mock_client
            .expect_block_results()
            .times(block_count)
            .returning(move |height| {
                let mut block_results = block_results.clone();
                block_results.height = height;

                Ok(block_results)
            });

        let token = CancellationToken::new();
        let (mut event_publisher, event_subcriber) =
            EventPublisher::new(mock_client, block_count * event_count_per_block);
        event_publisher.poll_interval = Duration::from_millis(10);
        let mut stream = event_subcriber.subscribe();

        let child_token = token.child_token();
        let handle = tokio::spawn(async move { event_publisher.run(child_token).await });

        for i in 1..(block_count * event_count_per_block + 1) {
            let event = stream.next().await;

            match i % event_count_per_block {
                0 => {
                    assert!(matches!(event, Some(Ok(Event::BlockEnd(..)))));
                }
                1 => {
                    assert!(matches!(event, Some(Ok(Event::BlockBegin(..)))));
                }
                _ => {
                    assert!(matches!(event, Some(Ok(Event::Abci { .. }))));
                }
            }
        }

        token.cancel();

        assert!(handle.await.is_ok());
    }

    fn random_event() -> abci::Event {
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
}
