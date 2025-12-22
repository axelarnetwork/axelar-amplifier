use std::time::Duration;

use error_stack::{Report, Result};
use events::Event;
use futures::{future, StreamExt, TryStreamExt};
use mockall::automock;
use report::LoggableError;
use serde::{Deserialize, Serialize};
use tendermint::block;
use thiserror::Error;
use tokio::sync::broadcast::{self, Sender};
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::Stream;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, instrument};
use valuable::Valuable;

use crate::asyncutil::future::RetryPolicy;
use crate::monitoring;
use crate::monitoring::metrics::Msg;
use crate::tm_client::TmClient;

pub mod event_filter;
pub mod stream;

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

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(default)]
pub struct Config {
    /// Maximum number of blocks to buffer for concurrent processing.
    ///
    /// - A value of 1 ensures sequential processing, preventing the event sub
    ///   from downloading events from multiple blocks simultaneously. This minimizes
    ///   memory usage but may slow down event processing.
    /// - Higher values enable parallel block processing, improving throughput but
    ///   increasing memory usage and potential resource contention.
    /// - Setting this too high may cause excessive memory consumption, while setting
    ///   it too low may lead to slower processing and underutilization of downstream
    ///   consumers.
    pub block_processing_buffer: usize,

    /// How often to poll the Axelar node for new blocks.
    ///
    /// This should generally match or be slightly less than the chain's block time.
    /// For example, with 1s block times, use `poll_interval = "1s"`.
    #[serde(with = "humantime_serde")]
    pub poll_interval: Duration,

    /// Duration to wait before retrying a failed block or event fetch operation.
    ///
    /// When fetching block data or events from the RPC fails, the system waits
    /// this duration before attempting again. This is independent of block time
    /// and is used for recovering from transient RPC errors.
    #[serde(with = "humantime_serde")]
    pub retry_delay: Duration,

    /// Maximum number of retry attempts for failed block or event fetch operations.
    ///
    /// After this many consecutive failures, the operation is aborted.
    /// Total maximum wait time before giving up = `retry_delay * retry_max_attempts`.
    pub retry_max_attempts: u64,

    /// Buffer size for the event stream.
    ///
    /// Maximum number of events to buffer before applying backpressure.
    pub stream_buffer_size: usize,

    /// Delay between processing consecutive blocks.
    ///
    /// To avoid inconsistencies (e.g. the block can be streamed but subsequent queries
    /// for the state show the block doesn't exist yet, especially when using load-balancers)
    /// blocks processing can be delayed by this parameter.
    #[serde(with = "humantime_serde")]
    pub delay: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            block_processing_buffer: 10,
            poll_interval: Duration::from_secs(1),
            retry_delay: Duration::from_secs(3),
            retry_max_attempts: 3,
            stream_buffer_size: 100000,
            delay: Duration::from_secs(1),
        }
    }
}

#[automock]
pub trait EventSub {
    fn subscribe(&self) -> impl Stream<Item = Result<Event, Error>> + Send + 'static;
}

#[derive(Clone, Debug)]
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

#[derive(Debug)]
pub struct EventPublisher<T: TmClient + Sync> {
    tm_client: T,
    poll_interval: Duration,
    tx: Sender<std::result::Result<Event, Error>>,
    delay: Duration,
    block_processing_buffer: usize,
    retry_policy: RetryPolicy,
    monitoring_client: monitoring::Client,
}

impl<T: TmClient + Sync + std::fmt::Debug> EventPublisher<T> {
    #[instrument]
    pub fn new(
        client: T,
        capacity: usize,
        delay: Duration,
        poll_interval: Duration,
        block_processing_buffer: usize,
        retry_policy: RetryPolicy,
        monitoring_client: monitoring::Client,
    ) -> (Self, EventSubscriber) {
        let (tx, _) = broadcast::channel(capacity);
        let publisher = EventPublisher {
            tm_client: client,
            poll_interval,
            tx: tx.clone(),
            delay,
            block_processing_buffer,
            retry_policy,
            monitoring_client,
        };
        let subscriber = EventSubscriber { tx };

        (publisher, subscriber)
    }

    #[instrument]
    pub async fn run(self, token: CancellationToken) -> Result<(), Error> {
        let block_stream = stream::blocks(&self.tm_client, self.poll_interval, self.delay)
            .filter(|_| future::ready(self.has_subscriber())); // skip processing blocks when no subscriber exists
        let event_stream = stream::events(
            &self.tm_client,
            block_stream,
            self.retry_policy,
            self.block_processing_buffer,
        )
        .take_until(token.cancelled());

        tokio::pin!(event_stream);
        while let Some(event) = event_stream.next().await {
            // error_stack::Report does not implement `Clone`, so we log the full error and pass on the latest context
            let event = event
                .inspect_err(|err| {
                    self.monitoring_client
                        .metrics()
                        .record_metric(Msg::EventPublisherError);

                    error!(
                        err = LoggableError::from(err).as_value(),
                        "failed to retrieve to events"
                    );
                })
                .map_err(|err| err.current_context().clone());

            let _ = self.tx.send(event).map_err(Report::new).inspect_err(|err| {
                self.monitoring_client
                    .metrics()
                    .record_metric(Msg::EventPublisherError);

                error!(
                    err = LoggableError::from(err).as_value(),
                    "failed to send event to subscribers"
                );
            });
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
    use std::time::Duration;

    use axelar_wasm_std::assert_err_contains;
    use error_stack::report;
    use events::Event;
    use futures::stream::StreamExt;
    use tendermint::{abci, block};
    use tokio_util::sync::CancellationToken;

    use crate::asyncutil::future::RetryPolicy;
    use crate::event_sub::{Error, EventPublisher, EventSub};
    use crate::monitoring::metrics::Msg;
    use crate::monitoring::test_utils;
    use crate::tm_client::{self, MockTmClient};

    // Test timing constants - explicit for clarity
    const POLL_INTERVAL: Duration = Duration::from_millis(100);
    const STREAM_DELAY: Duration = Duration::from_millis(50);
    const RETRY_DELAY: Duration = Duration::from_millis(200);

    fn test_block() -> tendermint::Block {
        serde_json::from_str(include_str!("../tests/axelar_block.json")).unwrap()
    }

    fn test_block_response(block: tendermint::Block) -> tm_client::BlockResponse {
        tm_client::BlockResponse {
            block_id: Default::default(),
            block,
        }
    }

    fn test_block_results(height: block::Height) -> tm_client::BlockResultsResponse {
        tm_client::BlockResultsResponse {
            height,
            begin_block_events: Some(vec![]),
            end_block_events: Some(vec![]),
            consensus_param_updates: None,
            txs_results: Some(vec![abci::types::ExecTxResult::default()]),
            validator_updates: vec![],
            app_hash: Default::default(),
            finalize_block_events: vec![],
        }
    }

    fn rpc_error() -> error_stack::Report<tendermint_rpc::Error> {
        report!(tendermint_rpc::Error::server("test error".to_string()))
    }

    fn create_publisher(
        mock: MockTmClient,
    ) -> (
        EventPublisher<MockTmClient>,
        super::EventSubscriber,
        tokio::sync::mpsc::Receiver<Msg>,
    ) {
        let (monitoring, metrics_rx) = test_utils::monitoring_client();
        let (publisher, subscriber) = EventPublisher::new(
            mock,
            100,
            STREAM_DELAY,
            POLL_INTERVAL,
            10,
            RetryPolicy::repeat_constant(RETRY_DELAY, 3),
            monitoring,
        );
        (publisher, subscriber, metrics_rx)
    }

    /// When no subscriber is listening, the publisher should still poll for new blocks
    /// but skip fetching block results (an optimization to avoid unnecessary RPC calls).
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn with_no_subscriber_blocks_are_polled_but_skips_block_results_query() {
        let mut mock = MockTmClient::new();
        let mut height = test_block().header().height;

        // Expectation: latest_block will be called 10 times, because the time will advance 10 * poll interval
        mock.expect_latest_block().times(10).returning(move || {
            height = height.increment();
            let mut block = test_block();
            block.header.height = height;

            Ok(test_block_response(block))
        });

        // Expectation: block_results should never be called when no subscriber exists
        mock.expect_block_results().never();

        let (publisher, subscriber, _) = create_publisher(mock);
        drop(subscriber);

        let token = CancellationToken::new();
        let handle = tokio::spawn(publisher.run(token.child_token()));

        // Advance time in small steps to allow other threads to run
        for _ in 0..100 {
            tokio::time::advance(POLL_INTERVAL / 10).await;
        }

        token.cancel();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn with_subscriber_streams_block_events() {
        let mut mock = MockTmClient::new();
        mock.expect_latest_block()
            .returning(move || Ok(test_block_response(test_block().clone())));
        mock.expect_block_results()
            .returning(move |h| Ok(test_block_results(h)));

        let (publisher, subscriber, _) = create_publisher(mock);

        let token = CancellationToken::new();
        let mut stream = subscriber.subscribe();
        let handle = tokio::spawn(publisher.run(token.child_token()));

        // Small time steps to allow task scheduling
        for _ in 0..10 {
            tokio::time::advance(POLL_INTERVAL / 10).await;
        }

        // Expectation: after poll interval is past, the block events should be accessible
        assert!(matches!(
            stream.next().await.unwrap(),
            Ok(Event::BlockBegin(_))
        ));
        assert!(matches!(
            stream.next().await.unwrap(),
            Ok(Event::BlockEnd(_))
        ));

        token.cancel();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn with_latest_block_error_propagates_error_to_subscriber() {
        let mut mock = MockTmClient::new();
        mock.expect_latest_block().returning(|| Err(rpc_error()));
        // Expectation: if the latest block query already fails, the block results will never be called
        mock.expect_block_results().never();

        let (publisher, subscriber, _) = create_publisher(mock);

        let token = CancellationToken::new();
        let mut stream = subscriber.subscribe();
        let handle = tokio::spawn(publisher.run(token.child_token()));

        // Small time steps to allow task scheduling
        for _ in 0..10 {
            tokio::time::advance(POLL_INTERVAL / 10).await;
        }

        assert_err_contains!(stream.next().await.unwrap(), Error, Error::LatestBlockQuery);

        token.cancel();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn with_block_results_error_propagates_error_to_subscriber() {
        let mut mock = MockTmClient::new();
        mock.expect_latest_block()
            .returning(move || Ok(test_block_response(test_block().clone())));
        mock.expect_block_results().returning(|_| Err(rpc_error()));

        let (publisher, subscriber, _) = create_publisher(mock);

        let token = CancellationToken::new();
        let mut stream = subscriber.subscribe();
        let handle = tokio::spawn(publisher.run(token.child_token()));

        // Small time steps to allow task scheduling
        for _ in 0..10 {
            tokio::time::advance(POLL_INTERVAL / 10).await;
        }

        assert_err_contains!(
            stream.next().await.unwrap(),
            Error,
            Error::BlockResultsQuery { .. }
        );

        token.cancel();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn with_error_records_error_metric() {
        let mut mock = MockTmClient::new();
        mock.expect_latest_block().returning(|| Err(rpc_error()));
        mock.expect_block_results().never();

        let (publisher, subscriber, mut metrics_rx) = create_publisher(mock);

        let token = CancellationToken::new();
        let mut stream = subscriber.subscribe();
        let handle = tokio::spawn(publisher.run(token.child_token()));

        // Small time steps to allow task scheduling
        for _ in 0..10 {
            tokio::time::advance(POLL_INTERVAL / 10).await;
        }

        // Consume the error event
        let _ = stream.next().await;

        // Verify metric was recorded
        assert_eq!(metrics_rx.recv().await.unwrap(), Msg::EventPublisherError);

        token.cancel();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn with_mixed_responses_streams_all_blocks_and_errors_in_order() {
        let mut height = test_block().header.height;

        // Prepare responses: Ok, Err, Ok, Err, Ok
        let mut responses = vec![
            Ok(test_block_response(test_block())),
            Err(rpc_error()),
            Ok(test_block_response({
                height = height.increment();
                let mut b = test_block();
                b.header.height = height;
                b
            })),
            Err(rpc_error()),
            Ok(test_block_response({
                height = height.increment();
                let mut b = test_block();
                b.header.height = height;
                b
            })),
        ]
        .into_iter();

        let mut mock = MockTmClient::new();
        // Expectation: called 5 times, because the time is advanced 5 * poll interval
        mock.expect_latest_block()
            .times(5)
            .returning(move || responses.next().unwrap());
        mock.expect_block_results()
            .returning(move |h| Ok(test_block_results(h)));

        let (publisher, subscriber, _) = create_publisher(mock);

        let token = CancellationToken::new();
        let mut stream = subscriber.subscribe();
        let handle = tokio::spawn(publisher.run(token.child_token()));

        // Advance time to process all 5 responses
        for _ in 0..50 {
            tokio::time::advance(POLL_INTERVAL / 10).await;
        }

        // Expectation: see all block events and all errors in the correct order
        assert!(matches!(
            stream.next().await.unwrap(),
            Ok(Event::BlockBegin(_))
        ));
        assert!(matches!(
            stream.next().await.unwrap(),
            Ok(Event::BlockEnd(_))
        ));
        assert_err_contains!(stream.next().await.unwrap(), Error, Error::LatestBlockQuery);
        assert!(matches!(
            stream.next().await.unwrap(),
            Ok(Event::BlockBegin(_))
        ));
        assert!(matches!(
            stream.next().await.unwrap(),
            Ok(Event::BlockEnd(_))
        ));
        assert_err_contains!(stream.next().await.unwrap(), Error, Error::LatestBlockQuery);
        assert!(matches!(
            stream.next().await.unwrap(),
            Ok(Event::BlockBegin(_))
        ));
        assert!(matches!(
            stream.next().await.unwrap(),
            Ok(Event::BlockEnd(_))
        ));

        token.cancel();
        handle.await.unwrap().unwrap();
    }
}
