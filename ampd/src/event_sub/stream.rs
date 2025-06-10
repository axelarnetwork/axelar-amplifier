use crate::asyncutil::future::{with_retry, RetryPolicy};
use crate::tm_client::TmClient;
use error_stack::ResultExt;
use events::Event;
use futures::{stream, Stream, StreamExt, TryFutureExt, TryStream};
use pin_project_lite::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use std::{future, iter};
use tendermint::block;
use tokio::time::interval;
use tokio_stream::wrappers::IntervalStream;

type Error = super::Error;
type Result<T> = error_stack::Result<T, Error>;

/// Returns a stream of block heights as the get generated on the blockchain.
/// To keep the load on the blockchain node manageable, the polling frequency is adjustable.
/// Because the blockchain state seems to be somewhat unstable when interacting with the latest state,
/// the stream can be delayed when returning the latest block.
///
/// Guarantees:
/// - the blockchain does not get queried more often than the poll_interval allows
/// - no blocks get omitted after starting the stream
/// - blocks get streamed in order
/// - no duplicates
/// - no delay when catching up, i.e. if the block height query returns a block that is n blocks
///   ahead of the previously seen latest block, all blocks leading up to that new latest block will get
///   streamed without delay
pub fn blocks<Client>(
    tm_client: &Client,
    poll_interval: Duration,
    stream_delay: Duration,
) -> impl Stream<Item = Result<block::Height>> + '_
where
    Client: TmClient + Sync,
{
    IntervalStream::new(interval(poll_interval))
        .then(|_each_tick| latest_block_height(tm_client))
        .dedup()
        .map(move |result| delay_blocks(result, stream_delay))
        .buffered(1) // so blocks can be filled in without dealing with futures
        .fill_gaps()
}

async fn latest_block_height<T: TmClient>(tm_client: &T) -> Result<block::Height> {
    tm_client
        .latest_block()
        .await
        .change_context(Error::LatestBlockQuery)
        .map(|res| res.block.header().height)
}

pub fn events<'a, T, S>(
    tm_client: &'a T,
    block_stream: S,
    retry_policy: RetryPolicy,
) -> impl Stream<Item = Result<Event>> + 'a
where
    T: TmClient,
    S: Stream<Item = Result<block::Height>> + 'a,
{
    block_stream
        .map(move |block_height| retrieve_all_block_events(tm_client, block_height, retry_policy))
        .buffered(super::BLOCK_PROCESSING_BUFFER)
        .flat_map(|result| {
            result.map_or_else(
                |err| stream::iter(vec![Err(err)]),
                |events| stream::iter(events.into_iter().map(Ok).collect::<Vec<_>>()),
            )
        })
}

async fn delay_blocks(
    result: Result<block::Height>,
    stream_delay: Duration,
) -> Result<block::Height> {
    match result {
        Ok(block) => {
            tokio::time::sleep(stream_delay).await;
            Ok(block)
        }
        Err(err) => Err(err),
    }
}

async fn retrieve_all_block_events<T>(
    tm_client: &T,
    block_height: Result<block::Height>,
    retry_policy: RetryPolicy,
) -> Result<Vec<Event>>
where
    T: TmClient,
{
    match block_height {
        Ok(block_height) => {
            with_retry(|| block_events(tm_client, block_height), retry_policy).await
        }
        Err(err) => Err(err),
    }
}
async fn block_events<T>(tm_client: &T, block_height: block::Height) -> Result<Vec<Event>>
where
    T: TmClient,
{
    let block_results =
        tm_client
            .block_results(block_height)
            .await
            .change_context(Error::BlockResultsQuery {
                block: block_height,
            })?;

    let begin_block_events = block_results.begin_block_events.into_iter().flatten();
    let tx_events = block_results
        .txs_results
        .into_iter()
        .flatten()
        .flat_map(|tx| tx.events);
    let end_block_events = block_results.end_block_events.into_iter().flatten();

    let events = begin_block_events
        .chain(tx_events)
        .chain(end_block_events)
        .map(|event| {
            Event::try_from(event).change_context(Error::EventDecoding {
                block: block_height,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(iter::once(Event::BlockBegin(block_height))
        .chain(events)
        .chain(iter::once(Event::BlockEnd(block_height)))
        .collect())
}

pin_project! {
    struct Dedup<S>
    where
        S: TryStream,
    {
        #[pin]
        stream: S,
        previous: Option<S::Ok>,
    }
}

trait DedupExt: TryStream + Sized {
    fn dedup(self) -> Dedup<Self> {
        Dedup {
            stream: self,
            previous: None,
        }
    }
}

impl<S> DedupExt for S where S: TryStream {}

impl<S> Stream for Dedup<S>
where
    S: TryStream,
    S::Ok: Clone + PartialEq,
{
    type Item = core::result::Result<S::Ok, S::Error>;
    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<core::result::Result<S::Ok, S::Error>>> {
        let mut me = self.as_mut().project();

        match me.stream.as_mut().try_poll_next(cx) {
            Poll::Ready(Some(Ok(current))) => {
                let previous = me.previous.replace(current.clone());

                match previous {
                    Some(previous) if previous == current => Poll::Pending,
                    _ => Poll::Ready(Some(Ok(current))),
                }
            }
            poll_result => poll_result,
        }
    }
}

pin_project! {
    struct FillGaps<S>
    where
        S: TryStream,
    {
        #[pin]
        stream: S,
        state: StreamState,
    }
}

#[derive(Debug, Copy, Clone)]
enum StreamState {
    Start,
    First {
        first: block::Height,
        streamed: bool,
    },
    BlocksAvailable {
        streamed: block::Height,
        latest: block::Height,
    },
    CaughtUp(block::Height),
}

impl StreamState {
    pub fn update_latest(self, new_latest: block::Height) -> Self {
        match self {
            StreamState::Start => StreamState::First {
                first: new_latest,
                streamed: false,
            },
            StreamState::First { first: latest, .. }
            | StreamState::BlocksAvailable { latest, .. }
            | StreamState::CaughtUp(latest)
                if latest >= new_latest =>
            {
                self
            }
            StreamState::First {
                first: streamed, ..
            }
            | StreamState::CaughtUp(streamed)
            | StreamState::BlocksAvailable { streamed, .. } => StreamState::BlocksAvailable {
                streamed,
                latest: new_latest,
            },
        }
    }

    pub fn stream(&mut self) -> Option<block::Height> {
        match *self {
            StreamState::Start | StreamState::CaughtUp(_) => None,
            StreamState::First { first, streamed } => {
                *self = StreamState::First {
                    first,
                    streamed: true,
                };
                (!streamed).then_some(first)
            }
            StreamState::BlocksAvailable { streamed, latest } => {
                let new_streamed = streamed.increment();

                *self = if new_streamed < latest {
                    StreamState::BlocksAvailable {
                        streamed: new_streamed,
                        latest,
                    }
                } else {
                    StreamState::CaughtUp(new_streamed)
                };

                Some(new_streamed)
            }
        }
    }
}

trait FillGapsExt
where
    Self: TryStream + Sized,
{
    fn fill_gaps(self) -> FillGaps<Self> {
        FillGaps {
            stream: self,
            state: StreamState::Start,
        }
    }
}

impl<S> FillGapsExt for S where S: TryStream {}

impl<S> Stream for FillGaps<S>
where
    Self: Sized,
    S: TryStream<Ok = block::Height>,
{
    type Item = core::result::Result<S::Ok, S::Error>;
    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<core::result::Result<S::Ok, S::Error>>> {
        let mut me = self.as_mut().project();

        loop {
            if let Some(to_stream) = me.state.stream() {
                return Poll::Ready(Some(Ok(to_stream)));
            }

            let new_latest = match me.stream.as_mut().try_poll_next(cx) {
                Poll::Ready(Some(Ok(new_latest))) => new_latest,
                poll_result => return poll_result,
            };
            *me.state = me.state.update_latest(new_latest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{block_results_response, random_event};
    use crate::asyncutil::future::RetryPolicy;
    use crate::event_sub::stream::{blocks, events};
    use crate::event_sub::Error;
    use crate::tm_client::{self, MockTmClient, TmClient};
    use axelar_wasm_std::{assert_err_contains, err_contains};
    use error_stack::report;
    use events::Event;
    use futures::{stream, StreamExt};
    use std::collections::HashMap;
    use std::env;
    use std::time::Duration;
    use tendermint::{abci, block};
    use tokio_util::sync::CancellationToken;

    #[tokio::test(start_paused = true)]
    async fn event_stream_should_stream_error_on_block_stream_errors_without_chain_call() {
        let mut tm_client = MockTmClient::new();

        // ensure no chain calls
        tm_client.expect_block_results().never();

        let expected_errs = vec![
            Err(report!(Error::LatestBlockQuery)),
            Err(report!(Error::LatestBlockQuery)),
            Err(report!(Error::LatestBlockQuery)),
        ];
        let expected_err_count = expected_errs.len();

        let retry_delay = Duration::from_secs(10);
        let retry_policy = RetryPolicy::RepeatConstant {
            sleep: retry_delay,
            max_attempts: 3,
        };

        let start = tokio::time::Instant::now();

        let actual: Vec<_> = events(&tm_client, stream::iter(expected_errs), retry_policy)
            .collect()
            .await;

        // ensure retry policy didn't kick in
        assert!(start.elapsed() < retry_delay);

        assert_eq!(actual.len(), expected_err_count);
        assert!(actual.iter().all(Result::is_err));
    }

    #[tokio::test(start_paused = true)]
    async fn event_stream_should_retry_events_retrieval() {
        let mut tm_client = MockTmClient::new();
        let mut call_count = 0;

        let expected_block_results: Vec<
            fn(block::Height) -> Result<tm_client::BlockResultsResponse, _>,
        > = vec![
            |_| {
                Err(report!(tendermint_rpc::Error::server(
                    "server error".to_string()
                )))
            },
            {
                |height| {
                    Ok(block_results_response(
                        height,
                        vec![],
                        vec![],
                        vec![abci::Event {
                            attributes: vec![abci::EventAttribute {
                                key: "???".to_string(),
                                value: "!!!".to_string(),
                                index: false,
                            }],
                            ..random_event()
                        }],
                    ))
                }
            },
            |height| {
                Ok(block_results_response(
                    height,
                    vec![random_event()],
                    vec![random_event()],
                    vec![random_event()],
                ))
            },
        ];

        tm_client
            .expect_block_results()
            .times(3)
            .returning(move |height| {
                call_count += 1;

                expected_block_results.get(call_count - 1).unwrap()(height)
            });

        let retry_policy = RetryPolicy::RepeatConstant {
            sleep: Duration::from_secs(100),
            max_attempts: 3,
        };
        let block_stream = stream::iter(vec![Ok(block::Height::from(1u32))]);
        let actual_results: Vec<_> = events(&tm_client, block_stream, retry_policy)
            .collect()
            .await;

        assert!(matches!(
            &actual_results[..],
            [
                Ok(Event::BlockBegin(_)),
                Ok(Event::Abci { .. }),
                Ok(Event::Abci { .. }),
                Ok(Event::Abci { .. }),
                Ok(Event::BlockEnd(_)),
            ]
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn event_stream_should_stream_event() {
        let mut tm_client = MockTmClient::new();
        tm_client
            .expect_block_results()
            .times(2)
            .returning(move |height| {
                if height == 1u32.into() {
                    Ok(block_results_response(
                        height,
                        vec![random_event()],
                        vec![random_event()],
                        vec![random_event()],
                    ))
                } else if height == 2u32.into() {
                    Ok(block_results_response(
                        height,
                        vec![random_event(), random_event()],
                        vec![random_event(), random_event()],
                        vec![random_event(), random_event()],
                    ))
                } else {
                    unreachable!()
                }
            });

        let retry_policy = RetryPolicy::RepeatConstant {
            sleep: Duration::from_millis(100),
            max_attempts: 3,
        };
        let block_stream = stream::iter(vec![Ok(1u32.into()), Ok(2u32.into())]);
        let stream = events(&tm_client, block_stream, retry_policy);

        let events: Vec<_> = stream.collect().await;

        assert!(matches!(
            &events[..],
            [
                Ok(Event::BlockBegin(_)),
                Ok(Event::Abci { .. }),
                Ok(Event::Abci { .. }),
                Ok(Event::Abci { .. }),
                Ok(Event::BlockEnd(_)),
                Ok(Event::BlockBegin(_)),
                Ok(Event::Abci { .. }),
                Ok(Event::Abci { .. }),
                Ok(Event::Abci { .. }),
                Ok(Event::Abci { .. }),
                Ok(Event::Abci { .. }),
                Ok(Event::Abci { .. }),
                Ok(Event::BlockEnd(_))
            ]
        ))
    }

    #[tokio::test(start_paused = true)]
    async fn block_stream_can_be_cancelled() {
        let block: tendermint::Block =
            serde_json::from_str(include_str!("../tests/axelar_block.json")).unwrap();
        let interval = std::time::Duration::from_millis(100);

        let token = CancellationToken::new();
        let child_token = token.child_token();
        let handle = tokio::spawn(async move {
            let mut tm_client = MockTmClient::new();
            tm_client.expect_latest_block().returning(move || {
                Ok(tm_client::BlockResponse {
                    block_id: Default::default(),
                    block: block.clone(),
                })
            });
            let stream = blocks(&tm_client, interval, Duration::from_secs(1))
                .take_until(child_token.cancelled());

            tokio::pin!(stream);
            while stream.next().await.is_some() {}
        });

        token.cancel();
        assert!(handle.await.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn block_stream_should_stream_error_if_subsequent_latest_block_height_query_fails() {
        let block: tendermint::Block =
            serde_json::from_str(include_str!("../tests/axelar_block.json")).unwrap();
        let interval = Duration::from_millis(100);

        let mut tm_client = MockTmClient::new();
        let mut call_count = 0;
        tm_client.expect_latest_block().times(3).returning(move || {
            call_count += 1;

            match call_count {
                1 => Ok(tm_client::BlockResponse {
                    block_id: Default::default(),
                    block: block.clone(),
                }),
                _ => Err(report!(tendermint_rpc::Error::server(
                    "server error".to_string()
                ))),
            }
        });

        let actual_results = blocks(&tm_client, interval, Duration::from_secs(1))
            .take(3)
            .collect::<Vec<_>>()
            .await;

        goldie::assert_debug!(actual_results
            .into_iter()
            .map(|result| result.map_err(|err| err.to_string()))
            .collect::<Vec<_>>());
    }

    #[tokio::test(start_paused = true)]
    async fn block_stream_should_stream_block_height() {
        let block: tendermint::Block =
            serde_json::from_str(include_str!("../tests/axelar_block.json")).unwrap();
        let height = block.header().height;
        let interval = Duration::from_secs(5);

        let mut tm_client = MockTmClient::new();
        let mut call_count = 0;
        let mut cur_block = block.clone();
        let token = CancellationToken::new();
        let child_token = token.child_token();
        tm_client.expect_latest_block().returning(move || {
            call_count += 1;

            match call_count {
                1 => Ok(tm_client::BlockResponse {
                    block_id: Default::default(),
                    block: cur_block.clone(),
                }),
                2 => {
                    cur_block.header.height = (height.value() + 3).try_into().unwrap();

                    Ok(tm_client::BlockResponse {
                        block_id: Default::default(),
                        block: cur_block.clone(),
                    })
                }
                3 => Err(report!(tendermint_rpc::Error::server(
                    "server error".to_string()
                ))),
                4 => {
                    cur_block.header.height = (height.value() + 9).try_into().unwrap();

                    Ok(tm_client::BlockResponse {
                        block_id: Default::default(),
                        block: cur_block.clone(),
                    })
                }
                _ => {
                    token.cancel();

                    Ok(tm_client::BlockResponse {
                        block_id: Default::default(),
                        block: cur_block.clone(),
                    })
                }
            }
        });

        let mut stream = blocks(&tm_client, interval, Duration::from_secs(1))
            .take_until(child_token.cancelled());

        let mut expected_height = height;
        tokio::pin!(stream);
        while let Some(result) = stream.next().await {
            match result {
                Ok(actual) => {
                    assert_eq!(actual, expected_height);
                    expected_height = expected_height.increment();
                }
                Err(err) => {
                    assert!(err_contains!(err, Error, Error::LatestBlockQuery));
                }
            }
        }

        // expected_height was incremented after the last check
        assert_eq!(height.value() + 9, expected_height.value() - 1);
    }
}
