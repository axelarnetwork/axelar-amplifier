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
use crate::monitoring::server::MetricsClient;
use crate::monitoring::MetricsMsg;
use crate::queue::queued_broadcaster::BroadcasterClient;

#[derive(Clone, Debug)]
pub struct HandlerInfo {
    pub chain_name: String,
    pub verifier_id: String,
    pub cast_votes: bool,
}

#[async_trait]
pub trait EventHandler {
    type Err: Context;
    async fn handle(&self, event: &Event) -> Result<Vec<Any>, Self::Err>;
    fn get_handler_info(&self) -> HandlerInfo;
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
    handler_label: String,
    handler: H,
    broadcaster: B,
    event_stream: S,
    event_processor_config: Config,
    token: CancellationToken,
    metric_client: MetricsClient,
) -> Result<(), Error>
where
    H: EventHandler,
    B: BroadcasterClient,
    S: Stream<Item = Result<Event, E>>,
    E: Context,
{
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
                metric_client.clone(),
            )
            .await?;
        }

        if let StreamStatus::Active(Event::BlockEnd(height)) = &stream_status {
            info!(
                handler = handler_label,
                height = height.value(),
                "handler finished processing block"
            );

            if let Err(err) = metric_client.record_metric(MetricsMsg::IncBlockReceived) {
                warn!( handler = handler_label,
                    height = height.value(),
                    err = %err,
                    "failed to record block received metric for block end event",
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
    metric_client: MetricsClient,
) -> Result<(), Error>
where
    H: EventHandler,
    B: BroadcasterClient,
{
    // if handlers run into errors we log them and then move on to the next event
    match future::with_retry(|| handler.handle(event), retry_policy).await {
        Ok(msgs) => {
            let handler_info = handler.get_handler_info();
            for msg in msgs {
                let broadcast_result = broadcaster.broadcast(msg.clone()).await;
                record_vote_metrics(&metric_client, &handler_info, &msg, &broadcast_result);
                if let Err(err) = broadcast_result {
                    warn!(
                        err = LoggableError::from(&err).as_value(),
                        "failed to broadcast message {:?} for event {}", msg, event
                    )
                }
            }
        }
        Err(err) => {
            warn!(
                err = LoggableError::from(&err).as_value(),
                "handler failed to process event {}", event,
            )
        }
    }

    Ok(())
}

fn record_vote_metrics(
    metric_client: &MetricsClient,
    handler_info: &HandlerInfo,
    msg: &Any,
    result: &std::result::Result<(), error_stack::Report<crate::queue::queued_broadcaster::Error>>,
) {
    if !handler_info.cast_votes {
        return;
    }

    let metric = match result {
        Ok(()) => MetricsMsg::IncSuccessVoteCasted {
            verifier_id: handler_info.verifier_id.clone(),
            chain_name: handler_info.chain_name.clone(),
        },
        Err(_) => MetricsMsg::IncFailedVoteCasted {
            verifier_id: handler_info.verifier_id.clone(),
            chain_name: handler_info.chain_name.clone(),
        },
    };

    if let Err(metric_error) = metric_client.record_metric(metric) {
        let metric_type = if result.is_ok() { "success" } else { "failed" };
        warn!(
            err = LoggableError::from(&metric_error).as_value(),
            "failed to record {} vote casted metric for message {:?}", metric_type, msg
        );
    }
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

enum StreamStatus {
    Active(Event),
    Closed,
    TimedOut,
}

#[cfg(test)]
mod tests {
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
    use reqwest::Url;
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;

    use crate::event_processor;
    use crate::event_processor::{consume_events, Config, Error, EventHandler, HandlerInfo};
    use crate::monitoring::server::test_utils::{
        test_dummy_server_setup, test_metrics_server_setup,
    };
    use crate::queue::queued_broadcaster::{Error as BroadcasterError, MockBroadcasterClient};

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

    fn create_test_handler_info() -> HandlerInfo {
        HandlerInfo {
            chain_name: "chain".to_string(),
            verifier_id: "verifier".to_string(),
            cast_votes: false,
        }
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
        handler
            .expect_get_handler_info()
            .times(events.len())
            .returning(create_test_handler_info);

        let broadcaster = MockBroadcasterClient::new();
        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );

        let (_server, metrics_client, _) = test_dummy_server_setup();

        let result_with_timeout = timeout(
            Duration::from_secs(1),
            consume_events(
                "handler".to_string(),
                handler,
                broadcaster,
                stream::iter(events),
                event_config,
                CancellationToken::new(),
                metrics_client,
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
        handler
            .expect_get_handler_info()
            .times(1)
            .returning(create_test_handler_info);

        let broadcaster = MockBroadcasterClient::new();
        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );
        let (_server, metrics_client, _) = test_dummy_server_setup();

        let result_with_timeout = timeout(
            Duration::from_secs(1),
            consume_events(
                "handler".to_string(),
                handler,
                broadcaster,
                stream::iter(events),
                event_config,
                CancellationToken::new(),
                metrics_client,
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
        let (_server, metrics_client, _) = test_dummy_server_setup();

        let result_with_timeout = timeout(
            Duration::from_secs(3),
            consume_events(
                "handler".to_string(),
                handler,
                broadcaster,
                stream::iter(events),
                event_config,
                CancellationToken::new(),
                metrics_client,
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
        handler
            .expect_get_handler_info()
            .times(events.len())
            .returning(create_test_handler_info);

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
        let (_server, metrics_client, _) = test_dummy_server_setup();

        let result_with_timeout = timeout(
            Duration::from_secs(3),
            consume_events(
                "handler".to_string(),
                handler,
                broadcaster,
                stream::iter(events),
                event_config,
                CancellationToken::new(),
                metrics_client,
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
        handler
            .expect_get_handler_info()
            .times(events.len())
            .returning(create_test_handler_info);

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
        let (_server, metrics_client, _) = test_dummy_server_setup();

        let result_with_timeout = timeout(
            Duration::from_secs(3),
            consume_events(
                "handler".to_string(),
                handler,
                broadcaster,
                stream::iter(events),
                event_config,
                CancellationToken::new(),
                metrics_client,
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
        handler
            .expect_get_handler_info()
            .times(4)
            .returning(create_test_handler_info);

        let broadcaster = MockBroadcasterClient::new();
        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );

        let token = CancellationToken::new();
        token.cancel();
        let (_server, metrics_client, _) = test_dummy_server_setup();
        let result_with_timeout = timeout(
            Duration::from_secs(1),
            consume_events(
                "handler".to_string(),
                handler,
                broadcaster,
                stream::iter(events),
                event_config,
                token,
                metrics_client,
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
        let (_server, metrics_client, _) = test_dummy_server_setup();
        let result_with_timeout = timeout(
            Duration::from_secs(1),
            consume_events(
                "handler".to_string(),
                handler,
                broadcaster,
                stream::pending::<Result<Event, Error>>(), // never returns any items so it can time out
                event_config,
                token,
                metrics_client,
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
                fn get_handler_info(&self) -> HandlerInfo;
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
        handler
            .expect_get_handler_info()
            .times(events.len())
            .returning(create_test_handler_info);

        let broadcaster = MockBroadcasterClient::new();
        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );
        let (bind_address, server, metrics_client, cancel_token) = test_metrics_server_setup();
        tokio::spawn(server.run(cancel_token.clone()));

        let result_with_timeout = timeout(
            Duration::from_secs(3),
            consume_events(
                "handler".to_string(),
                handler,
                broadcaster,
                stream::iter(events),
                event_config,
                cancel_token.clone(),
                metrics_client,
            ),
        )
        .await;

        assert!(result_with_timeout.is_ok());
        tokio::time::sleep(Duration::from_millis(100)).await;
        let base_url = Url::parse(&format!("http://{}", bind_address.unwrap())).unwrap();
        let metrics_url = base_url.join("metrics").unwrap();
        let response = reqwest::get(metrics_url).await.unwrap();
        let metrics_text = response.text().await.unwrap();
        assert!(metrics_text.contains(&format!("blocks_received {}", num_block_ends)));

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

        handler
            .expect_get_handler_info()
            .once()
            .returning(create_test_handler_info);

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

        let (bind_address, server, metrics_client, cancel_token) = test_metrics_server_setup();
        tokio::spawn(server.run(cancel_token.clone()));

        let result_with_timeout = timeout(
            Duration::from_secs(3),
            consume_events(
                "handler".to_string(),
                handler,
                broadcaster,
                stream::iter(events),
                event_config,
                cancel_token.clone(),
                metrics_client,
            ),
        )
        .await;

        assert!(result_with_timeout.is_ok());
        assert!(result_with_timeout.unwrap().is_ok());

        tokio::time::sleep(Duration::from_millis(100)).await;

        let base_url = Url::parse(&format!("http://{}", bind_address.unwrap())).unwrap();
        let metrics_url = base_url.join("metrics").unwrap();
        let response = reqwest::get(metrics_url).await.unwrap();
        let metrics_text = response.text().await.unwrap();

        assert!(!metrics_text.contains(
            "verifier_votes_casted_successful{chain_name=\"chain\",verifier_id=\"verifier\"}"
        ));
        assert!(!metrics_text.contains(
            "verifier_votes_casted_failed{chain_name=\"chain\",verifier_id=\"verifier\"}"
        ));
        assert!(!metrics_text.contains(
            "verifier_votes_casted_success_rate{chain_name=\"chain\",verifier_id=\"verifier\"}"
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

        handler
            .expect_get_handler_info()
            .once()
            .returning(|| HandlerInfo {
                chain_name: "ethereum".to_string(),
                verifier_id: "axelar1abc".to_string(),
                cast_votes: true,
            });

        let event_config = setup_event_config(
            Duration::from_secs(1),
            Duration::from_secs(1000),
            Duration::from_secs(1),
        );

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

        let (bind_address, server, metrics_client, cancel_token) = test_metrics_server_setup();
        tokio::spawn(server.run(cancel_token.clone()));

        let result_with_timeout = timeout(
            Duration::from_secs(3),
            consume_events(
                "handler".to_string(),
                handler,
                broadcaster,
                stream::iter(events),
                event_config,
                cancel_token.clone(),
                metrics_client,
            ),
        )
        .await;

        assert!(result_with_timeout.is_ok());
        assert!(result_with_timeout.unwrap().is_ok());

        tokio::time::sleep(Duration::from_millis(100)).await;

        let base_url = Url::parse(&format!("http://{}", bind_address.unwrap())).unwrap();
        let metrics_url = base_url.join("metrics").unwrap();
        let response = reqwest::get(metrics_url).await.unwrap();
        let metrics_text = response.text().await.unwrap();
        println!("metrics_text: {}", metrics_text);

        assert!(metrics_text.contains("verifier_votes_casted_successful{chain_name=\"ethereum\",verifier_id=\"axelar1abc\"} 2"));
        assert!(metrics_text.contains(
            "verifier_votes_casted_failed{chain_name=\"ethereum\",verifier_id=\"axelar1abc\"} 1"
        ));
        assert!(metrics_text.contains("verifier_votes_casted_success_rate{chain_name=\"ethereum\",verifier_id=\"axelar1abc\"} 0.6666666666666666"));

        cancel_token.cancel();
    }
}
