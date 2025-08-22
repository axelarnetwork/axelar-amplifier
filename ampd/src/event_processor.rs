use std::time::Duration;

use async_trait::async_trait;
use cosmrs::Any;
use error_stack::{Context, Report, Result};
use events::Event;
use futures::{future, pin_mut, Stream, StreamExt, TryStreamExt};
use report::LoggableError;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{info, instrument, warn};
use valuable::Valuable;

use crate::asyncutil::future::{with_retry, RetryPolicy};
use crate::asyncutil::task::TaskError;
use crate::monitoring::metrics;
use crate::monitoring::metrics::{Msg, Stage};
use crate::{broadcast, cosmos, event_sub, monitoring};

// Maximum number of messages to enqueue for broadcasting concurrently.
// - Controls parallelism when enqueueing messages to the broadcast queue
// - Higher values increase throughput for processing many messages at once
// - Lower values reduce resource consumption
// - Setting is balanced based on network capacity and system resources
const TX_BROADCAST_BUFFER_SIZE: usize = 10;

#[async_trait]
pub trait EventHandler {
    type Err: Context;

    async fn handle(&self, event: &Event) -> Result<Vec<Any>, Self::Err>;
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("could not consume events from stream")]
    EventStream,
    #[error("handler stopped prematurely")]
    Tasks(#[from] TaskError),
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct Config {
    #[serde(with = "humantime_serde")]
    pub retry_delay: Duration,
    pub retry_max_attempts: u64,
    #[serde(with = "humantime_serde")]
    pub stream_timeout: Duration,
    pub stream_buffer_size: usize,
    #[serde(with = "humantime_serde")]
    pub delay: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            retry_delay: Duration::from_secs(1),
            retry_max_attempts: 3,
            stream_timeout: Duration::from_secs(15),
            stream_buffer_size: 100000,
            delay: Duration::from_secs(1),
        }
    }
}

/// Let the `handler` consume events from the `event_stream`. The token is checked for cancellation
/// at the end of each consumed block or when the `event_stream` times out. If the token is cancelled or the
/// `event_stream` is closed, the function returns
#[instrument(fields(handler = %handler_label), skip_all)]
pub async fn consume_events<H, S, C>(
    handler_label: String,
    handler: H,
    event_stream: S,
    event_processor_config: Config,
    token: CancellationToken,
    msg_queue_client: broadcast::MsgQueueClient<C>,
    monitoring_client: monitoring::Client,
) -> Result<(), Error>
where
    H: EventHandler,
    S: Stream<Item = Result<Event, event_sub::Error>>,
    C: cosmos::CosmosClient + Clone,
{
    let Config {
        retry_delay,
        retry_max_attempts,
        stream_timeout,
        ..
    } = event_processor_config;
    let handler_retry = RetryPolicy::repeat_constant(retry_delay, retry_max_attempts);

    let event_stream =
        tokio_stream::StreamExt::timeout_repeating(event_stream, time::interval(stream_timeout));
    let event_stream = event_stream
        .map(|event| match event {
            Ok(Ok(event)) => StreamStatus::Ok(event),
            Ok(Err(err)) => StreamStatus::Error(err),
            Err(_) => StreamStatus::TimedOut,
        })
        .inspect(|event| log_block_end_event(event, &monitoring_client))
        .take_while(should_task_continue(token));
    pin_mut!(event_stream);

    while let Some(event) = event_stream.next().await {
        match event {
            StreamStatus::Ok(event) => {
                handle_event(
                    &handler,
                    &msg_queue_client,
                    &event,
                    handler_retry,
                    &monitoring_client,
                )
                .await?;
            }
            StreamStatus::Error(err) => return Err(err.change_context(Error::EventStream)),
            StreamStatus::TimedOut => {
                warn!("event stream timed out");
                monitoring_client
                    .metrics()
                    .record_metric(Msg::EventStreamTimeout);
            }
        }
    }

    Ok(())
}

#[instrument(fields(event = %event), skip_all)]
async fn handle_event<H, C>(
    handler: &H,
    msg_queue_client: &broadcast::MsgQueueClient<C>,
    event: &Event,
    retry_policy: RetryPolicy,
    monitoring_client: &monitoring::Client,
) -> Result<(), Error>
where
    H: EventHandler,
    C: cosmos::CosmosClient + Clone,
{
    let (res, elapsed) =
        metrics::timed(|| async { with_retry(|| handler.handle(event), retry_policy).await }).await;

    monitoring_client.metrics().record_metric(Msg::StageResult {
        stage: Stage::EventHandling,
        success: res.is_ok(),
        duration: elapsed,
    });

    match res {
        Ok(msgs) => {
            tokio_stream::iter(msgs)
                .map(|msg| async { msg_queue_client.clone().enqueue_and_forget(msg).await })
                .buffered(TX_BROADCAST_BUFFER_SIZE)
                .inspect_err(|err| {
                    warn!(
                        err = LoggableError::from(err).as_value(),
                        "failed to enqueue message for broadcasting"
                    );
                    monitoring_client
                        .metrics()
                        .record_metric(Msg::MessageEnqueueError);
                })
                .collect::<Vec<_>>()
                .await;
        }
        // if handlers run into errors we log them and then move on to the next event
        Err(err) => {
            warn!(
                err = LoggableError::from(&err).as_value(),
                "handler failed to process event {}", event,
            )
        }
    }

    Ok(())
}

fn should_task_continue(token: CancellationToken) -> impl Fn(&StreamStatus) -> future::Ready<bool> {
    move |event| match event {
        StreamStatus::Ok(Event::BlockBegin(_)) | StreamStatus::TimedOut => {
            future::ready(!token.is_cancelled())
        }
        _ => future::ready(true),
    }
}

fn log_block_end_event(event: &StreamStatus, monitoring_client: &monitoring::Client) {
    if let StreamStatus::Ok(Event::BlockEnd(height)) = event {
        info!(height = height.value(), "handler finished processing block");

        monitoring_client
            .metrics()
            .record_metric(Msg::BlockReceived);
    }
}

#[derive(Debug)]
enum StreamStatus {
    Ok(Event),
    Error(Report<event_sub::Error>),
    TimedOut,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use async_trait::async_trait;
    use axelar_wasm_std::assert_err_contains;
    use cosmos_sdk_proto::cosmos::auth::v1beta1::QueryAccountResponse;
    use cosmos_sdk_proto::cosmos::bank::v1beta1::QueryBalanceResponse;
    use cosmos_sdk_proto::cosmos::base::abci::v1beta1::GasInfo;
    use cosmos_sdk_proto::cosmos::base::v1beta1::Coin;
    use cosmos_sdk_proto::cosmos::tx::v1beta1::SimulateResponse;
    use cosmrs::bank::MsgSend;
    use cosmrs::tendermint::chain;
    use cosmrs::tx::Msg;
    use cosmrs::{AccountId, Any};
    use error_stack::{report, Result};
    use events::Event;
    use futures::{stream, StreamExt};
    use mockall::mock;
    use monitoring::{metrics, test_utils};
    use report::ErrorExt;
    use tokio::sync::mpsc::Receiver;
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;
    use tonic::Status;

    use crate::broadcast::test_utils::create_base_account;
    use crate::broadcast::DecCoin;
    use crate::event_processor::{consume_events, Config, Error, EventHandler};
    use crate::types::{random_cosmos_public_key, TMAddress};
    use crate::{broadcast, cosmos, event_sub, monitoring, PREFIX};

    #[derive(Error, Debug)]
    pub enum EventHandlerError {
        #[error("failed")]
        Failed,
    }

    mock! {
            EventHandler{}

            #[async_trait]
            impl EventHandler for EventHandler {
                type Err = EventHandlerError;

                async fn handle(&self, event: &Event) -> Result<Vec<Any>, EventHandlerError>;
            }
    }

    fn dummy_msg() -> Any {
        MsgSend {
            from_address: AccountId::new("", &[1, 2, 3]).unwrap(),
            to_address: AccountId::new("", &[4, 5, 6]).unwrap(),
            amount: vec![],
        }
        .to_any()
        .unwrap()
    }

    fn setup_event_config(
        retry_delay_value: Duration,
        stream_timeout_value: Duration,
        delay: Duration,
    ) -> Config {
        Config {
            retry_delay: retry_delay_value,
            retry_max_attempts: 3,
            stream_timeout: stream_timeout_value,
            stream_buffer_size: 100000,
            delay,
        }
    }

    fn setup_client(address: &TMAddress) -> cosmos::MockCosmosClient {
        let mut cosmos_client = cosmos::MockCosmosClient::new();
        let base_account = create_base_account(address);

        cosmos_client.expect_account().return_once(move |_| {
            Ok(QueryAccountResponse {
                account: Some(Any::from_msg(&base_account).unwrap()),
            })
        });
        cosmos_client.expect_balance().return_once(move |_| {
            Ok(QueryBalanceResponse {
                balance: Some(Coin {
                    denom: "uaxl".to_string(),
                    amount: "1000000".to_string(),
                }),
            })
        });

        cosmos_client
    }

    fn mock_client_with_simulate_error(address: TMAddress) -> cosmos::MockCosmosClient {
        let mut mock_client = setup_client(&address);

        mock_client.expect_clone().times(1).returning(move || {
            let base_account = create_base_account(&address);
            let mut mock_client = cosmos::MockCosmosClient::new();
            mock_client.expect_account().return_once(move |_| {
                Ok(QueryAccountResponse {
                    account: Some(Any::from_msg(&base_account).unwrap()),
                })
            });
            mock_client
                .expect_simulate()
                .return_once(|_| Err(Status::internal("internal error").into_report()));
            mock_client
        });

        mock_client
    }

    #[tokio::test(start_paused = true)]
    async fn stop_when_stream_closes() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: chain::Id = "test-chain-id".parse().unwrap();
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";
        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );
        let events: Vec<Result<Event, event_sub::Error>> = vec![
            Ok(Event::BlockEnd(0_u32.into())),
            Ok(Event::BlockEnd(1_u32.into())),
            Ok(Event::BlockEnd(3_u32.into())),
        ];

        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .times(events.len())
            .returning(|_| Ok(vec![]));

        let mock_client = setup_client(&address);

        let broadcaster = broadcast::Broadcaster::builder()
            .client(mock_client)
            .chain_id(chain_id)
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();

        let (monitoring_client, _) = test_utils::monitoring_client();

        let (_, msg_queue_client) = broadcast::MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            100,
            Duration::from_millis(500),
            monitoring_client.clone(),
        );

        let result = consume_events(
            "handler".to_string(),
            handler,
            stream::iter(events),
            event_config,
            CancellationToken::new(),
            msg_queue_client,
            monitoring_client,
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn return_error_when_stream_fails() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: chain::Id = "test-chain-id".parse().unwrap();
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";
        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );
        let events: Vec<Result<Event, event_sub::Error>> = vec![
            Ok(Event::BlockEnd(0_u32.into())),
            Err(report!(event_sub::Error::LatestBlockQuery)),
        ];

        let mut handler = MockEventHandler::new();
        handler.expect_handle().return_once(|_| Ok(vec![]));

        let mock_client = setup_client(&address);

        let broadcaster = broadcast::Broadcaster::builder()
            .client(mock_client)
            .chain_id(chain_id)
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();
        let (monitoring_client, _) = test_utils::monitoring_client();

        let (_, msg_queue_client) = broadcast::MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            100,
            Duration::from_millis(500),
            monitoring_client.clone(),
        );

        let result = consume_events(
            "handler".to_string(),
            handler,
            stream::iter(events),
            event_config,
            CancellationToken::new(),
            msg_queue_client,
            monitoring_client,
        )
        .await;
        assert_err_contains!(result, Error, Error::EventStream);
    }

    #[tokio::test(start_paused = true)]
    async fn return_ok_when_handler_fails() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: chain::Id = "test-chain-id".parse().unwrap();
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";
        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );
        let events: Vec<Result<Event, event_sub::Error>> = vec![Ok(Event::BlockEnd(0_u32.into()))];

        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .times(3)
            .returning(|_| Err(report!(EventHandlerError::Failed)));

        let mock_client = setup_client(&address);

        let broadcaster = broadcast::Broadcaster::builder()
            .client(mock_client)
            .chain_id(chain_id)
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();
        let (monitoring_client, _) = test_utils::monitoring_client();
        let (_, msg_queue_client) = broadcast::MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            100,
            Duration::from_millis(500),
            monitoring_client.clone(),
        );

        let result = consume_events(
            "handler".to_string(),
            handler,
            stream::iter(events),
            event_config,
            CancellationToken::new(),
            msg_queue_client,
            monitoring_client,
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn return_ok_and_broadcast_when_handler_succeeds() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: chain::Id = "test-chain-id".parse().unwrap();
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";
        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );
        let events: Vec<Result<Event, event_sub::Error>> = vec![Ok(Event::BlockEnd(0_u32.into()))];

        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .return_once(|_| Ok(vec![dummy_msg(), dummy_msg()]));

        let mut mock_client = setup_client(&address);
        mock_client.expect_clone().times(2).returning(move || {
            let base_account = create_base_account(&address);

            let mut mock_client = cosmos::MockCosmosClient::new();
            mock_client.expect_account().return_once(move |_| {
                Ok(QueryAccountResponse {
                    account: Some(Any::from_msg(&base_account).unwrap()),
                })
            });
            mock_client.expect_simulate().return_once(|_| {
                Ok(SimulateResponse {
                    gas_info: Some(GasInfo {
                        gas_wanted: 50,
                        gas_used: 50,
                    }),
                    ..Default::default()
                })
            });

            mock_client
        });

        let broadcaster = broadcast::Broadcaster::builder()
            .client(mock_client)
            .chain_id(chain_id)
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();
        let (monitoring_client, _) = test_utils::monitoring_client();
        let (msg_queue, msg_queue_client) = broadcast::MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            100,
            Duration::from_millis(500),
            monitoring_client.clone(),
        );

        let result = consume_events(
            "handler".to_string(),
            handler,
            stream::iter(events),
            event_config,
            CancellationToken::new(),
            msg_queue_client,
            monitoring_client,
        )
        .await;
        assert!(result.is_ok());
        let msgs = msg_queue.collect::<Vec<_>>().await;
        assert_eq!(msgs.len(), 1);
        let msgs = msgs.first().unwrap();
        assert_eq!(msgs.as_ref().len(), 2)
    }

    #[tokio::test(start_paused = true)]
    async fn return_ok_when_broadcaster_fails() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: chain::Id = "test-chain-id".parse().unwrap();
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";
        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );
        let events: Vec<Result<Event, event_sub::Error>> = vec![Ok(Event::BlockEnd(0_u32.into()))];

        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .return_once(|_| Ok(vec![dummy_msg(), dummy_msg()]));

        let mut mock_client = setup_client(&address);
        mock_client.expect_clone().times(2).returning(move || {
            let base_account = create_base_account(&address);

            let mut mock_client = cosmos::MockCosmosClient::new();
            mock_client.expect_account().return_once(move |_| {
                Ok(QueryAccountResponse {
                    account: Some(Any::from_msg(&base_account).unwrap()),
                })
            });
            mock_client
                .expect_simulate()
                .return_once(|_| Err(Status::internal("internal error").into_report()));

            mock_client
        });

        let broadcaster = broadcast::Broadcaster::builder()
            .client(mock_client)
            .chain_id(chain_id)
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();
        let (monitoring_client, _) = test_utils::monitoring_client();
        let (msg_queue, msg_queue_client) = broadcast::MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            100,
            Duration::from_millis(500),
            monitoring_client.clone(),
        );

        let result = consume_events(
            "handler".to_string(),
            handler,
            stream::iter(events),
            event_config,
            CancellationToken::new(),
            msg_queue_client,
            monitoring_client,
        )
        .await;
        let msgs = msg_queue.collect::<Vec<_>>().await;
        assert!(result.is_ok());
        assert_eq!(msgs.len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn react_to_cancellation_at_block_end() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: chain::Id = "test-chain-id".parse().unwrap();
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";
        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );
        let token = CancellationToken::new();
        let events: Vec<Result<Event, event_sub::Error>> = vec![
            Ok(Event::BlockEnd(0_u32.into())),
            Ok(Event::BlockEnd(1_u32.into())),
            Ok(Event::BlockEnd(2_u32.into())),
            Ok(Event::BlockEnd(3_u32.into())),
            Ok(Event::BlockBegin(4_u32.into())),
        ];

        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .times(events.len() - 1)
            .returning(|_| Ok(vec![]));

        let mock_client = setup_client(&address);

        let broadcaster = broadcast::Broadcaster::builder()
            .client(mock_client)
            .chain_id(chain_id)
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();
        let (monitoring_client, _) = test_utils::monitoring_client();
        let (_, msg_queue_client) = broadcast::MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            100,
            Duration::from_millis(500),
            monitoring_client.clone(),
        );

        token.cancel();
        let result = consume_events(
            "handler".to_string(),
            handler,
            stream::iter(events),
            event_config,
            token.child_token(),
            msg_queue_client,
            monitoring_client,
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn react_to_cancellation_on_timeout() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: chain::Id = "test-chain-id".parse().unwrap();
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";
        let token = CancellationToken::new();
        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(1),
        );

        let mock_client = setup_client(&address);

        let broadcaster = broadcast::Broadcaster::builder()
            .client(mock_client)
            .chain_id(chain_id)
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();
        let (monitoring_client, _) = test_utils::monitoring_client();
        let (_, msg_queue_client) = broadcast::MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            100,
            Duration::from_millis(500),
            monitoring_client.clone(),
        );

        token.cancel();
        let result = consume_events(
            "handler".to_string(),
            MockEventHandler::new(),
            stream::pending(),
            event_config,
            token.child_token(),
            msg_queue_client,
            monitoring_client,
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn block_end_events_increment_blocks_received_metric() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: chain::Id = "test-chain-id".parse().unwrap();
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";
        let events: Vec<Result<Event, event_sub::Error>> = vec![
            Ok(Event::BlockEnd(0_u32.into())),
            Ok(Event::BlockEnd(1_u32.into())),
        ];
        let num_block_ends = 2;
        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .times(events.len())
            .returning(|_| Ok(vec![]));

        let mock_client = setup_client(&address);

        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );

        let broadcaster = broadcast::Broadcaster::builder()
            .client(mock_client)
            .chain_id(chain_id)
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();
        let (monitoring_client, mut receiver) = test_utils::monitoring_client();
        let (_, msg_queue_client) = broadcast::MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            100,
            Duration::from_millis(500),
            monitoring_client.clone(),
        );

        let cancel_token = CancellationToken::new();

        let result_with_timeout = timeout(
            Duration::from_secs(3),
            consume_events(
                "handler".to_string(),
                handler,
                stream::iter(events),
                event_config,
                cancel_token.clone(),
                msg_queue_client,
                monitoring_client,
            ),
        )
        .await;

        assert!(result_with_timeout.is_ok());

        for _ in 0..num_block_ends {
            expect_metric_msg(&mut receiver, |m| matches!(m, metrics::Msg::BlockReceived)).await;
        }

        while let Some(metric) = receiver.recv().await {
            assert!(
                !matches!(metric, metrics::Msg::BlockReceived),
                "unexpected BlockReceived metric"
            );
        }

        cancel_token.cancel();
    }

    #[tokio::test(start_paused = true)]
    async fn should_record_event_handling_metrics_successfully() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: chain::Id = "test-chain-id".parse().unwrap();
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";
        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );

        let events: Vec<Result<Event, event_sub::Error>> = vec![
            Ok(Event::BlockEnd(0_u32.into())),
            Ok(Event::BlockEnd(1_u32.into())),
        ];

        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .times(4)
            .returning(|event| match event {
                Event::BlockEnd(height) => match height.value() {
                    0 => Ok(vec![dummy_msg()]),
                    1 => Err(report!(EventHandlerError::Failed)),
                    _ => Ok(vec![]),
                },
                _ => Ok(vec![]),
            });

        let mut mock_client = setup_client(&address);
        mock_client.expect_clone().times(1).returning(move || {
            let base_account = create_base_account(&address);
            let mut mock_client = cosmos::MockCosmosClient::new();
            mock_client.expect_account().return_once(move |_| {
                Ok(QueryAccountResponse {
                    account: Some(Any::from_msg(&base_account).unwrap()),
                })
            });
            mock_client
                .expect_simulate()
                .return_once(|_| Err(Status::internal("simulation failed").into_report()));
            mock_client
        });

        let broadcaster = broadcast::Broadcaster::builder()
            .client(mock_client)
            .chain_id(chain_id)
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();
        let (monitoring_client, mut receiver) = test_utils::monitoring_client();

        let (_, msg_queue_client) = broadcast::MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            100,
            Duration::from_millis(500),
            monitoring_client.clone(),
        );

        let _ = consume_events(
            "handler".to_string(),
            handler,
            stream::iter(events),
            event_config,
            CancellationToken::new(),
            msg_queue_client,
            monitoring_client,
        )
        .await;

        expect_metric_msg(&mut receiver, |m| {
            matches!(
                m,
                metrics::Msg::StageResult {
                    stage: metrics::Stage::EventHandling,
                    success: true,
                    ..
                }
            )
        })
        .await;

        expect_metric_msg(&mut receiver, |m| {
            matches!(
                m,
                metrics::Msg::StageResult {
                    stage: metrics::Stage::EventHandling,
                    success: false,
                    ..
                }
            )
        })
        .await;

        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn should_record_event_timeout_metric_successfully() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: chain::Id = "test-chain-id".parse().unwrap();
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";
        let token = CancellationToken::new();
        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(1),
        );

        let mock_client = setup_client(&address);

        let broadcaster = broadcast::Broadcaster::builder()
            .client(mock_client)
            .chain_id(chain_id)
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();
        let (monitoring_client, mut receiver) = test_utils::monitoring_client();
        let (_, msg_queue_client) = broadcast::MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            100,
            Duration::from_millis(500),
            monitoring_client.clone(),
        );

        let task = tokio::spawn(consume_events(
            "handler".to_string(),
            MockEventHandler::new(),
            stream::pending(),
            event_config,
            token.child_token(),
            msg_queue_client,
            monitoring_client,
        ));

        tokio::time::advance(Duration::from_secs(2)).await;

        let metric = receiver.recv().await.unwrap();
        assert_eq!(metric, metrics::Msg::EventStreamTimeout);

        token.cancel();
        let _ = task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn should_record_msg_enqueue_error_when_msg_simulate_failed() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: chain::Id = "test-chain-id".parse().unwrap();
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";
        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );
        let events: Vec<Result<Event, event_sub::Error>> = vec![Ok(Event::BlockEnd(0_u32.into()))];

        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .return_once(|_| Ok(vec![dummy_msg()]));

        let mock_client = mock_client_with_simulate_error(address);

        let broadcaster = broadcast::Broadcaster::builder()
            .client(mock_client)
            .chain_id(chain_id)
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();
        let (monitoring_client, mut receiver) = test_utils::monitoring_client();
        let (_, msg_queue_client) = broadcast::MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            100,
            Duration::from_millis(500),
            monitoring_client.clone(),
        );

        let _ = consume_events(
            "handler".to_string(),
            handler,
            stream::iter(events),
            event_config,
            CancellationToken::new(),
            msg_queue_client,
            monitoring_client,
        )
        .await;

        expect_metric_msg(&mut receiver, |m| {
            matches!(m, metrics::Msg::MessageEnqueueError)
        })
        .await;

        assert!(receiver.try_recv().is_err());
    }

    /// Waits for a metric Msg that matches the specified variant kind to appear in the stream.
    /// This function is used in tests to ignore irrelevant messages and wait for specific metrics.
    async fn expect_metric_msg<F>(receiver: &mut Receiver<metrics::Msg>, matcher: F)
    where
        F: Fn(&metrics::Msg) -> bool,
    {
        while let Some(metric) = receiver.recv().await {
            if matcher(&metric) {
                return;
            }
        }
        panic!("monitoring channel closed before expected metric was observed");
    }
}
