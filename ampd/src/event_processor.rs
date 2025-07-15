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
use crate::monitoring::metrics::Msg;
use crate::{broadcaster_v2, cosmos, event_sub, monitoring};

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
    msg_queue_client: broadcaster_v2::MsgQueueClient<C>,
    metric_client: monitoring::Client,
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
        .inspect(|event| log_block_end_event(event, &handler_label, &metric_client))
        .take_while(should_task_continue(token));
    pin_mut!(event_stream);

    while let Some(event) = event_stream.next().await {
        match event {
            StreamStatus::Ok(event) => {
                handle_event(&handler, &msg_queue_client, &event, handler_retry).await?;
            }
            StreamStatus::Error(err) => return Err(err.change_context(Error::EventStream)),
            StreamStatus::TimedOut => {
                warn!("event stream timed out");
            }
        }
    }

    Ok(())
}

#[instrument(fields(event = %event), skip_all)]
async fn handle_event<H, C>(
    handler: &H,
    msg_queue_client: &broadcaster_v2::MsgQueueClient<C>,
    event: &Event,
    retry_policy: RetryPolicy,
) -> Result<(), Error>
where
    H: EventHandler,
    C: cosmos::CosmosClient + Clone,
{
    match with_retry(|| handler.handle(event), retry_policy).await {
        Ok(msgs) => {
            tokio_stream::iter(msgs)
                .map(|msg| async { msg_queue_client.clone().enqueue_and_forget(msg).await })
                .buffered(TX_BROADCAST_BUFFER_SIZE)
                .inspect_err(|err| {
                    warn!(
                        err = LoggableError::from(err).as_value(),
                        "failed to enqueue message for broadcasting"
                    )
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

fn log_block_end_event(
    event: &StreamStatus,
    handler_label: &str,
    metric_client: &monitoring::Client,
) {
    if let StreamStatus::Ok(Event::BlockEnd(height)) = event {
        info!(height = height.value(), "handler finished processing block");

        if let Err(err) = metric_client.metrics().record_metric(Msg::IncBlockReceived) {
            warn!( handler = handler_label,
                height = height.value(),
                err = %err,
                "failed to record block received metric"
            );
        }
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
    use std::net::SocketAddr;
    use std::time::Duration;

    use async_trait::async_trait;
    use axelar_wasm_std::assert_err_contains;
    use cosmos_sdk_proto::cosmos::auth::v1beta1::{BaseAccount, QueryAccountResponse};
    use cosmos_sdk_proto::cosmos::base::abci::v1beta1::GasInfo;
    use cosmos_sdk_proto::cosmos::tx::v1beta1::SimulateResponse;
    use cosmrs::bank::MsgSend;
    use cosmrs::tendermint::chain;
    use cosmrs::tx::Msg;
    use cosmrs::{AccountId, Any};
    use error_stack::{report, Result};
    use events::Event;
    use futures::{stream, StreamExt};
    use mockall::mock;
    use report::ErrorExt;
    use reqwest::Url;
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;
    use tonic::Status;

    use crate::event_processor::{consume_events, Config, Error, EventHandler};
    use crate::types::{random_cosmos_public_key, TMAddress};
    use crate::{broadcaster_v2, cosmos, event_sub, monitoring, PREFIX};

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

    #[tokio::test(start_paused = true)]
    async fn stop_when_stream_closes() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: chain::Id = "test-chain-id".parse().unwrap();
        let account_number = 42u64;
        let sequence = 10u64;
        let base_account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number,
            sequence,
        };
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

        let mut mock_client = cosmos::MockCosmosClient::new();
        mock_client.expect_account().return_once(move |_| {
            Ok(QueryAccountResponse {
                account: Some(Any::from_msg(&base_account).unwrap()),
            })
        });

        let broadcaster = broadcaster_v2::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let (_, msg_queue_client) = broadcaster_v2::MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            100,
            Duration::from_millis(500),
        );

        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();

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
        let account_number = 42u64;
        let sequence = 10u64;
        let base_account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number,
            sequence,
        };
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

        let mut mock_client = cosmos::MockCosmosClient::new();
        mock_client.expect_account().return_once(move |_| {
            Ok(QueryAccountResponse {
                account: Some(Any::from_msg(&base_account).unwrap()),
            })
        });

        let broadcaster = broadcaster_v2::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let (_, msg_queue_client) = broadcaster_v2::MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            100,
            Duration::from_millis(500),
        );

        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();

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
        let account_number = 42u64;
        let sequence = 10u64;
        let base_account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number,
            sequence,
        };
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

        let mut mock_client = cosmos::MockCosmosClient::new();
        mock_client.expect_account().return_once(move |_| {
            Ok(QueryAccountResponse {
                account: Some(Any::from_msg(&base_account).unwrap()),
            })
        });

        let broadcaster = broadcaster_v2::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let (_, msg_queue_client) = broadcaster_v2::MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            100,
            Duration::from_millis(500),
        );

        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();

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
        let account_number = 42u64;
        let sequence = 10u64;
        let base_account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number,
            sequence,
        };
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

        let mut mock_client = cosmos::MockCosmosClient::new();
        mock_client.expect_account().return_once(move |_| {
            Ok(QueryAccountResponse {
                account: Some(Any::from_msg(&base_account).unwrap()),
            })
        });
        mock_client.expect_clone().times(2).returning(|| {
            let mut mock_client = cosmos::MockCosmosClient::new();
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

        let broadcaster = broadcaster_v2::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let (msg_queue, msg_queue_client) = broadcaster_v2::MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            100,
            Duration::from_millis(500),
        );

        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();

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
        let account_number = 42u64;
        let sequence = 10u64;
        let base_account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number,
            sequence,
        };
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

        let mut mock_client = cosmos::MockCosmosClient::new();
        mock_client.expect_account().return_once(move |_| {
            Ok(QueryAccountResponse {
                account: Some(Any::from_msg(&base_account).unwrap()),
            })
        });
        mock_client.expect_clone().times(2).returning(|| {
            let mut mock_client = cosmos::MockCosmosClient::new();
            mock_client
                .expect_simulate()
                .return_once(|_| Err(Status::internal("internal error").into_report()));

            mock_client
        });

        let broadcaster = broadcaster_v2::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let (msg_queue, msg_queue_client) = broadcaster_v2::MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            100,
            Duration::from_millis(500),
        );

        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();

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
        let account_number = 42u64;
        let sequence = 10u64;
        let base_account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number,
            sequence,
        };
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

        let mut mock_client = cosmos::MockCosmosClient::new();
        mock_client.expect_account().return_once(move |_| {
            Ok(QueryAccountResponse {
                account: Some(Any::from_msg(&base_account).unwrap()),
            })
        });

        let broadcaster = broadcaster_v2::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let (_, msg_queue_client) = broadcaster_v2::MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            100,
            Duration::from_millis(500),
        );

        token.cancel();
        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();
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
        let account_number = 42u64;
        let sequence = 10u64;
        let base_account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number,
            sequence,
        };
        let token = CancellationToken::new();
        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(1),
        );

        let mut mock_client = cosmos::MockCosmosClient::new();
        mock_client.expect_account().return_once(move |_| {
            Ok(QueryAccountResponse {
                account: Some(Any::from_msg(&base_account).unwrap()),
            })
        });

        let broadcaster = broadcaster_v2::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let (_, msg_queue_client) = broadcaster_v2::MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            100,
            Duration::from_millis(500),
        );

        token.cancel();
        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();
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

    #[tokio::test(start_paused = true)]
    async fn block_end_events_increment_blocks_received_metric() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: chain::Id = "test-chain-id".parse().unwrap();
        let account_number = 42u64;
        let sequence = 10u64;
        let base_account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number,
            sequence,
        };
        let events: Vec<Result<Event, event_sub::Error>> = vec![
            Ok(Event::BlockEnd(0_u32.into())),
            Ok(Event::BlockEnd(1_u32.into())),
            Ok(Event::BlockEnd(2_u32.into())),
            Ok(Event::BlockBegin(3_u32.into())),
            Ok(Event::BlockEnd(4_u32.into())),
            Ok(Event::BlockBegin(5_u32.into())),
            Ok(Event::BlockEnd(6_u32.into())),
        ];
        let num_block_ends = 5;
        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .times(events.len())
            .returning(|_| Ok(vec![]));

        let mut mock_client = cosmos::MockCosmosClient::new();
        mock_client.expect_account().return_once(move |_| {
            Ok(QueryAccountResponse {
                account: Some(Any::from_msg(&base_account).unwrap()),
            })
        });

        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );

        let broadcaster = broadcaster_v2::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let (_, msg_queue_client) = broadcaster_v2::MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            100,
            Duration::from_millis(500),
        );

        let bind_addr = monitoring::Config::enabled().bind_address;
        let (server, monitoring_client) = monitoring::Server::new(bind_addr).unwrap();
        let cancel_token = CancellationToken::new();
        tokio::spawn(server.run(cancel_token.clone()));

        tokio::time::sleep(Duration::from_millis(100)).await;

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
        tokio::time::sleep(Duration::from_millis(100)).await;

        let base_url = Url::parse(&format!("http://{}", bind_addr.unwrap())).unwrap();
        let metrics_url = base_url.join("metrics").unwrap();
        let response = reqwest::get(metrics_url).await.unwrap();
        let metrics_text = response.text().await.unwrap();
        assert!(metrics_text.contains(&format!("blocks_received_total {}", num_block_ends)));

        cancel_token.cancel();
    }
}
