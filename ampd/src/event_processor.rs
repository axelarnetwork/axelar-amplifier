use std::pin::Pin;
use std::time::Duration;

use async_trait::async_trait;
use cosmrs::Any;
use error_stack::{Context, Result, ResultExt};
use events::Event;
use futures::StreamExt;
use report::LoggableError;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time::timeout;
use tokio_stream::Stream;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use valuable::Valuable;

use crate::asyncutil::future::{self, RetryPolicy};
use crate::asyncutil::task::TaskError;
use crate::handlers::config::HandlerInfo;
use crate::monitoring;
use crate::monitoring::metrics::Msg;
use crate::queue::queued_broadcaster::BroadcasterClient;

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
pub async fn consume_events<H, B, S, E>(
    handler: H,
    broadcaster: B,
    event_stream: S,
    event_processor_config: Config,
    token: CancellationToken,
    monitoring_client: monitoring::Client,
    handler_info: HandlerInfo,
) -> Result<(), Error>
where
    H: EventHandler,
    B: BroadcasterClient,
    S: Stream<Item = Result<Event, E>>,
    E: Context,
{
    let handler_label = &handler_info.label;
    let mut event_stream = Box::pin(event_stream);
    loop {
        let stream_status =
            retrieve_next_event(&mut event_stream, event_processor_config.stream_timeout)
                .await
                .change_context(Error::EventStream)?;

        if let StreamStatus::Active(event) = &stream_status {
            handle_event(
                &handler,
                &broadcaster,
                event,
                RetryPolicy::RepeatConstant {
                    sleep: event_processor_config.retry_delay,
                    max_attempts: event_processor_config.retry_max_attempts,
                },
                &monitoring_client,
                handler_info.clone(),
            )
            .await?;
        }

        if let StreamStatus::Active(Event::BlockEnd(height)) = &stream_status {
            info!(
                handler = handler_label,
                height = height.value(),
                "handler finished processing block"
            );

            if let Err(err) = monitoring_client
                .metrics()
                .record_metric(Msg::BlockReceived)
            {
                warn!( handler = handler_label,
                    height = height.value(),
                    err = %err,
                    "failed to record block received metric",
                );
            }
        }

        if should_task_stop(stream_status, &token) {
            return Ok(());
        }
    }
}

async fn handle_event<H, B>(
    handler: &H,
    broadcaster: &B,
    event: &Event,
    retry_policy: RetryPolicy,
    monitoring_client: &monitoring::Client,
    handler_info: HandlerInfo,
) -> Result<(), Error>
where
    H: EventHandler,
    B: BroadcasterClient,
{
    // if handlers run into errors we log them and then move on to the next event
    match future::with_retry(|| handler.handle(event), retry_policy).await {
        Ok(msgs) => {
            for msg in msgs {
                let broadcast_result = broadcaster.broadcast(msg.clone()).await;
                record_vote_metrics(monitoring_client, handler_info.clone(), &broadcast_result);
                if let Err(err) = broadcast_result {
                    warn!(
                        err = LoggableError::from(&err).as_value(),
                        "failed to broadcast message {:?} for event {}", msg, event
                    )
                }
            }
        }
        Err(err) => {
            record_vote_failure(monitoring_client, handler_info.clone());
            warn!(
                err = LoggableError::from(&err).as_value(),
                "handler failed to process event {}", event,
            )
        }
    }

    Ok(())
}

async fn retrieve_next_event<S, E>(
    event_stream: &mut Pin<Box<S>>,
    stream_timeout: Duration,
) -> Result<StreamStatus, E>
where
    S: Stream<Item = Result<Event, E>>,
    E: Context,
{
    let status = match timeout(stream_timeout, event_stream.next()).await {
        Err(_) => StreamStatus::TimedOut,
        Ok(None) => StreamStatus::Closed,
        Ok(Some(event)) => StreamStatus::Active(event?),
    };
    Ok(status)
}

fn should_task_stop(stream_status: StreamStatus, token: &CancellationToken) -> bool {
    match stream_status {
        StreamStatus::Active(Event::BlockEnd(_)) | StreamStatus::TimedOut
            if token.is_cancelled() =>
        {
            true
        }
        StreamStatus::Closed => true,
        _ => false,
    }
}

fn record_vote_metrics(
    monitoring_client: &monitoring::Client,
    handler_info: HandlerInfo,
    result: &std::result::Result<(), error_stack::Report<crate::queue::queued_broadcaster::Error>>,
) {
    if !handler_info.cast_votes {
        return;
    }

    let metric_msg = match result {
        Ok(()) => Msg::VoteCastSucceeded {
            verifier_id: handler_info.verifier_id,
            chain_name: handler_info.chain_name,
        },
        Err(_) => Msg::VoteFailed {
            verifier_id: handler_info.verifier_id,
            chain_name: handler_info.chain_name,
        },
    };

    if let Err(metric_error) = monitoring_client.metrics().record_metric(metric_msg) {
        let metric_type = if result.is_ok() {
            "succeeded"
        } else {
            "failed"
        };
        warn!(
            err = %metric_error,
             "failed to record {} vote metrics",
             metric_type,
        );
    }
}

fn record_vote_failure(monitoring_client: &monitoring::Client, handler_info: HandlerInfo) {
    if !handler_info.cast_votes {
        return;
    }

    if let Err(metric_error) = monitoring_client.metrics().record_metric(Msg::VoteFailed {
        verifier_id: handler_info.verifier_id,
        chain_name: handler_info.chain_name,
    }) {
        warn!(
            err = %metric_error,
            "failed to record failed vote metric",
        );
    }
}

enum StreamStatus {
    Active(Event),
    Closed,
    TimedOut,
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::time::Duration;

    use assert_ok::assert_ok;
    use async_trait::async_trait;
    use cosmrs::bank::MsgSend;
    use cosmrs::tx::Msg;
    use cosmrs::{AccountId, Any};
    use error_stack::{report, Result};
    use events::Event;
    use futures::stream;
    use mockall::mock;
    use rand::random;
    use reqwest::Url;
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;

    use crate::event_processor::{consume_events, Config, Error, EventHandler};
    use crate::handlers::config::HandlerInfo;
    use crate::queue::queued_broadcaster::{Error as BroadcasterError, MockBroadcasterClient};
    use crate::{event_processor, monitoring};

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
    fn setup_handler_info(cast_votes: bool) -> HandlerInfo {
        HandlerInfo {
            label: "handler".to_string(),
            verifier_id: "verifier_id".to_string(),
            chain_name: "chain_name".to_string(),
            cast_votes,
        }
    }

    fn localhost_with_random_port() -> Option<SocketAddrV4> {
        Some(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), random()))
    }

    #[tokio::test]
    async fn stop_when_stream_closes() {
        let events: Vec<Result<Event, event_processor::Error>> = vec![
            Ok(Event::BlockEnd(0_u32.into())),
            Ok(Event::BlockEnd(1_u32.into())),
            Ok(Event::BlockEnd(3_u32.into())),
        ];

        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .times(events.len())
            .returning(|_| Ok(vec![]));

        let broadcaster = MockBroadcasterClient::new();
        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );

        let (_, monitoring_client) = monitoring::Server::new(None).unwrap();

        let result_with_timeout = timeout(
            Duration::from_secs(1),
            consume_events(
                handler,
                broadcaster,
                stream::iter(events),
                event_config,
                CancellationToken::new(),
                monitoring_client,
                setup_handler_info(false),
            ),
        )
        .await;

        assert!(result_with_timeout.is_ok());
        assert!(result_with_timeout.unwrap().is_ok());
    }

    #[tokio::test]
    async fn return_error_when_stream_fails() {
        let events: Vec<Result<Event, event_processor::Error>> = vec![
            Ok(Event::BlockEnd(0_u32.into())),
            Err(report!(Error::EventStream)),
        ];

        let mut handler = MockEventHandler::new();
        handler.expect_handle().times(1).returning(|_| Ok(vec![]));

        let broadcaster = MockBroadcasterClient::new();
        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );
        let (_, monitoring_client) = monitoring::Server::new(None).unwrap();

        let result_with_timeout = timeout(
            Duration::from_secs(1),
            consume_events(
                handler,
                broadcaster,
                stream::iter(events),
                event_config,
                CancellationToken::new(),
                monitoring_client,
                setup_handler_info(false),
            ),
        )
        .await;

        assert!(result_with_timeout.is_ok());
        assert!(result_with_timeout.unwrap().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn return_ok_when_handler_fails() {
        let events: Vec<Result<Event, event_processor::Error>> =
            vec![Ok(Event::BlockEnd(0_u32.into()))];

        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .times(3)
            .returning(|_| Err(report!(EventHandlerError::Failed)));

        let broadcaster = MockBroadcasterClient::new();
        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );
        let (_, monitoring_client) = monitoring::Server::new(None).unwrap();

        let result_with_timeout = timeout(
            Duration::from_secs(3),
            consume_events(
                handler,
                broadcaster,
                stream::iter(events),
                event_config,
                CancellationToken::new(),
                monitoring_client,
                setup_handler_info(false),
            ),
        )
        .await;

        assert!(result_with_timeout.is_ok());
        assert!(result_with_timeout.unwrap().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn return_ok_and_broadcast_when_handler_succeeds() {
        let events: Vec<Result<Event, event_processor::Error>> =
            vec![Ok(Event::BlockEnd(0_u32.into()))];

        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .once()
            .returning(|_| Ok(vec![dummy_msg(), dummy_msg()]));

        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );
        let mut broadcaster = MockBroadcasterClient::new();
        broadcaster
            .expect_broadcast()
            .times(2)
            .returning(|_| Ok(()));
        let (_, monitoring_client) = monitoring::Server::new(None).unwrap();

        let result_with_timeout = timeout(
            Duration::from_secs(3),
            consume_events(
                handler,
                broadcaster,
                stream::iter(events),
                event_config,
                CancellationToken::new(),
                monitoring_client,
                setup_handler_info(false),
            ),
        )
        .await;

        assert!(result_with_timeout.is_ok());
        assert!(result_with_timeout.unwrap().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn return_ok_when_broadcaster_fails() {
        let events: Vec<Result<Event, event_processor::Error>> =
            vec![Ok(Event::BlockEnd(0_u32.into()))];

        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .once()
            .returning(|_| Ok(vec![dummy_msg(), dummy_msg()]));

        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );
        let mut broadcaster = MockBroadcasterClient::new();
        broadcaster
            .expect_broadcast()
            .times(2)
            .returning(|_| Err(report!(BroadcasterError::EstimateFee)));
        let (_, monitoring_client) = monitoring::Server::new(None).unwrap();

        let result_with_timeout = timeout(
            Duration::from_secs(3),
            consume_events(
                handler,
                broadcaster,
                stream::iter(events),
                event_config,
                CancellationToken::new(),
                monitoring_client,
                setup_handler_info(false),
            ),
        )
        .await;

        assert_ok!(assert_ok!(result_with_timeout));
    }

    #[tokio::test]
    async fn react_to_cancellation_at_block_end() {
        let events: Vec<Result<Event, event_processor::Error>> = vec![
            Ok(Event::BlockBegin(0_u32.into())),
            Ok(Event::BlockBegin(1_u32.into())),
            Ok(Event::BlockBegin(2_u32.into())),
            Ok(Event::BlockEnd(3_u32.into())),
            Ok(Event::BlockBegin(4_u32.into())),
        ];

        let mut handler = MockEventHandler::new();
        handler.expect_handle().times(4).returning(|_| Ok(vec![]));

        let broadcaster = MockBroadcasterClient::new();
        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );

        let token = CancellationToken::new();
        token.cancel();
        let (_, monitoring_client) = monitoring::Server::new(None).unwrap();
        let result_with_timeout = timeout(
            Duration::from_secs(1),
            consume_events(
                handler,
                broadcaster,
                stream::iter(events),
                event_config,
                token,
                monitoring_client,
                setup_handler_info(false),
            ),
        )
        .await;

        assert!(result_with_timeout.is_ok());
        assert!(result_with_timeout.unwrap().is_ok());
    }

    #[tokio::test]
    async fn react_to_cancellation_on_timeout() {
        let handler = MockEventHandler::new();

        let broadcaster = MockBroadcasterClient::new();
        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(0),
            Duration::from_secs(1),
        );

        let token = CancellationToken::new();
        token.cancel();
        let (_, monitoring_client) = monitoring::Server::new(None).unwrap();
        let result_with_timeout = timeout(
            Duration::from_secs(1),
            consume_events(
                handler,
                broadcaster,
                stream::pending::<Result<Event, Error>>(), // never returns any items so it can time out
                event_config,
                token,
                monitoring_client,
                setup_handler_info(false),
            ),
        )
        .await;

        assert!(result_with_timeout.is_ok());
        assert!(result_with_timeout.unwrap().is_ok());
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
        let events: Vec<Result<Event, event_processor::Error>> = vec![
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

        let broadcaster = MockBroadcasterClient::new();
        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );
        let bind_addr = localhost_with_random_port();
        let (server, monitoring_client) = monitoring::Server::new(bind_addr).unwrap();
        let cancel_token = CancellationToken::new();
        tokio::spawn(server.run(cancel_token.clone()));

        tokio::time::sleep(Duration::from_millis(100)).await;

        let result_with_timeout = timeout(
            Duration::from_secs(3),
            consume_events(
                handler,
                broadcaster,
                stream::iter(events),
                event_config,
                cancel_token.clone(),
                monitoring_client,
                setup_handler_info(false),
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

    #[tokio::test(start_paused = true)]
    async fn non_voting_handler_successful_broadcast_does_not_record_vote_metrics() {
        let events: Vec<Result<Event, event_processor::Error>> =
            vec![Ok(Event::BlockEnd(0_u32.into()))];

        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .once()
            .returning(|_| Ok(vec![dummy_msg(), dummy_msg()]));

        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );

        let mut broadcaster = MockBroadcasterClient::new();
        broadcaster
            .expect_broadcast()
            .times(2)
            .returning(|_| Ok(()));

        let bind_addr = localhost_with_random_port();
        let (server, monitoring_client) = monitoring::Server::new(bind_addr).unwrap();
        let cancel_token = CancellationToken::new();
        tokio::spawn(server.run(cancel_token.clone()));

        tokio::time::sleep(Duration::from_millis(100)).await;

        let result_with_timeout = timeout(
            Duration::from_secs(3),
            consume_events(
                handler,
                broadcaster,
                stream::iter(events),
                event_config,
                cancel_token.clone(),
                monitoring_client,
                setup_handler_info(false),
            ),
        )
        .await;

        assert!(result_with_timeout.is_ok());
        assert!(result_with_timeout.unwrap().is_ok());

        tokio::time::sleep(Duration::from_millis(100)).await;

        let base_url = Url::parse(&format!("http://{}", bind_addr.unwrap())).unwrap();
        let metrics_url = base_url.join("metrics").unwrap();
        let response = reqwest::get(metrics_url).await.unwrap();
        let metrics_text = response.text().await.unwrap();

        assert!(!metrics_text.contains(
             "verifier_votes_casted_successful{chain_name=\"chain_name\",verifier_id=\"verifier_id\"}"
         ));
        assert!(!metrics_text.contains(
            "verifier_votes_failed_total{chain_name=\"chain_name\",verifier_id=\"verifier_id\"}"
        ));
        assert!(!metrics_text.contains(
            "verifier_votes_cast_success_rate{chain_name=\"chain_name\",verifier_id=\"verifier_id\"}"
        ));

        cancel_token.cancel();
    }

    #[tokio::test(start_paused = true)]
    async fn voting_handler_mixed_success_failure_broadcast_records_correct_metrics() {
        let events: Vec<Result<Event, event_processor::Error>> =
            vec![Ok(Event::BlockEnd(0_u32.into()))];

        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .once()
            .returning(|_| Ok(vec![dummy_msg(), dummy_msg(), dummy_msg()]));

        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );

        let bind_addr = localhost_with_random_port();
        let (server, monitoring_client) = monitoring::Server::new(bind_addr).unwrap();
        let cancel_token = CancellationToken::new();
        tokio::spawn(server.run(cancel_token.clone()));

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut broadcaster = MockBroadcasterClient::new();
        broadcaster.expect_broadcast().times(3).returning(|_| {
            static mut COUNTER: u32 = 0;
            unsafe {
                COUNTER += 1;
                if COUNTER == 2 {
                    Err(report!(BroadcasterError::EstimateFee))
                } else {
                    Ok(())
                }
            }
        });

        let result_with_timeout = timeout(
            Duration::from_secs(3),
            consume_events(
                handler,
                broadcaster,
                stream::iter(events),
                event_config,
                cancel_token.clone(),
                monitoring_client,
                setup_handler_info(true),
            ),
        )
        .await;

        assert!(result_with_timeout.is_ok());
        assert!(result_with_timeout.unwrap().is_ok());

        tokio::time::sleep(Duration::from_millis(100)).await;

        let base_url = Url::parse(&format!("http://{}", bind_addr.unwrap())).unwrap();
        let metrics_url = base_url.join("metrics").unwrap();
        let response = reqwest::get(metrics_url).await.unwrap();
        let metrics_text = response.text().await.unwrap();

        assert!(metrics_text.contains("verifier_votes_cast_successful_total{chain_name=\"chain_name\",verifier_id=\"verifier_id\"} 2"));
        assert!(metrics_text.contains(
            "verifier_votes_failed_total{chain_name=\"chain_name\",verifier_id=\"verifier_id\"} 1"
        ));
        assert!(metrics_text.contains(
            "verifier_votes_cast_success_rate{chain_name=\"chain_name\",verifier_id=\"verifier_id\"} 0.6666666666666666"
        ));

        cancel_token.cancel();
    }

    #[tokio::test(start_paused = true)]
    async fn event_processor_handles_metrics_recording_with_disabled_server() {
        let events: Vec<Result<Event, event_processor::Error>> = vec![
            Ok(Event::BlockEnd(0_u32.into())),
            Ok(Event::BlockEnd(1_u32.into())),
            Ok(Event::BlockEnd(2_u32.into())),
        ];

        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .times(events.len())
            .returning(|_| Ok(vec![dummy_msg()]));

        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );

        let mut broadcaster = MockBroadcasterClient::new();
        broadcaster
            .expect_broadcast()
            .times(events.len())
            .returning(|_| Ok(()));

        let (server, monitoring_client) = monitoring::Server::new(None).unwrap();
        let cancel = CancellationToken::new();
        tokio::spawn(server.run(cancel.clone()));

        tokio::time::sleep(Duration::from_millis(100)).await;

        let result_with_timeout = timeout(
            Duration::from_secs(3),
            consume_events(
                handler,
                broadcaster,
                stream::iter(events),
                event_config,
                CancellationToken::new(),
                monitoring_client,
                setup_handler_info(true),
            ),
        )
        .await;

        assert!(result_with_timeout.is_ok());
        assert!(result_with_timeout.unwrap().is_ok());

        cancel.cancel();
    }

    #[tokio::test(start_paused = true)]
    async fn voting_handler_failure_records_vote_failure_metrics_correctly() {
        let events: Vec<Result<Event, event_processor::Error>> =
            vec![Ok(Event::BlockEnd(0_u32.into()))];

        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .times(3)
            .returning(|_| Err(report!(EventHandlerError::Failed)));

        let broadcaster = MockBroadcasterClient::new();
        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );

        let bind_addr = localhost_with_random_port();
        let (server, monitoring_client) = monitoring::Server::new(bind_addr).unwrap();
        let cancel_token = CancellationToken::new();
        tokio::spawn(server.run(cancel_token.clone()));

        let result_with_timeout = timeout(
            Duration::from_secs(3),
            consume_events(
                handler,
                broadcaster,
                stream::iter(events),
                event_config,
                CancellationToken::new(),
                monitoring_client,
                setup_handler_info(true),
            ),
        )
        .await;

        assert!(result_with_timeout.is_ok());
        assert!(result_with_timeout.unwrap().is_ok());

        tokio::time::sleep(Duration::from_millis(100)).await;

        let base_url = Url::parse(&format!("http://{}", bind_addr.unwrap())).unwrap();
        let metrics_url = base_url.join("metrics").unwrap();
        let response = reqwest::get(metrics_url).await.unwrap();
        let metrics_text = response.text().await.unwrap();

        assert!(metrics_text.contains(
            "verifier_votes_failed_total{chain_name=\"chain_name\",verifier_id=\"verifier_id\"} 1"
        ));
        assert!(metrics_text.contains(
            "verifier_votes_cast_success_rate{chain_name=\"chain_name\",verifier_id=\"verifier_id\"} 0"
        ));
        assert!(metrics_text.contains(
            "verifier_votes_cast_successful_total{chain_name=\"chain_name\",verifier_id=\"verifier_id\"} 0"
        ));

        cancel_token.cancel();
    }
}
