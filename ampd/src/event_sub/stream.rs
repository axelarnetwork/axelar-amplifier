use std::fmt::Debug;
use std::iter;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use error_stack::ResultExt;
use events::Event;
use futures::{stream, Stream, StreamExt, TryStream};
use pin_project_lite::pin_project;
use tendermint::block;
use tokio::time::interval;
use tokio_stream::wrappers::IntervalStream;
use tracing::instrument;

use crate::asyncutil::future::{with_retry, RetryPolicy};
use crate::tm_client::{BlockResultsResponse, TmClient};

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
#[instrument]
pub fn blocks<Client>(
    tm_client: &Client,
    poll_interval: Duration,
    stream_delay: Duration,
) -> impl Stream<Item = Result<block::Height>> + '_
where
    Client: TmClient + Sync + Debug,
{
    IntervalStream::new(interval(poll_interval))
        .then(|_each_tick| latest_block_height(tm_client))
        .strictly_increasing_values()
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

/// Returns a stream of blockchain events from the provided block height stream.
/// Events are retrieved for each block height and include begin block, transaction, and end block events.
/// The function automatically retries failed event retrievals according to the specified retry policy.
///
/// Each block in the stream produces the following event sequence:
/// 1. `Event::BlockBegin` - marks the start of block processing
/// 2. All ABCI events from the block (begin_block, transactions, end_block)
/// 3. `Event::BlockEnd` - marks the end of block processing
///
/// Guarantees:
/// - events are streamed in the order they appear in blocks
/// - failed block height queries from the input stream are propagated as errors
/// - failed event retrievals are retried according to the retry policy
/// - all events from a successfully queried block are included in the stream
/// - block processing maintains the sequential order of the input stream
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
        .flat_map(|result| result.map_or_else(|err| stream::iter(vec![Err(err)]), stream::iter))
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
) -> Result<Vec<Result<Event>>>
where
    T: TmClient,
{
    match block_height {
        Ok(block_height) => with_retry(|| block_results(tm_client, block_height), retry_policy)
            .await
            .map(block_events),
        Err(err) => Err(err),
    }
}

async fn block_results<T>(
    tm_client: &T,
    block_height: block::Height,
) -> Result<BlockResultsResponse>
where
    T: TmClient,
{
    tm_client
        .block_results(block_height)
        .await
        .change_context(Error::BlockResultsQuery {
            block: block_height,
        })
}

fn block_events(block_results: BlockResultsResponse) -> Vec<Result<Event>> {
    let begin_block_events = block_results.begin_block_events.into_iter().flatten();
    let tx_events = block_results
        .txs_results
        .into_iter()
        .flatten()
        .flat_map(|tx| tx.events);
    let end_block_events = block_results.end_block_events.into_iter().flatten();

    let events: Vec<Result<Event>> = begin_block_events
        .chain(tx_events)
        .chain(end_block_events)
        .map(|event| {
            Event::try_from(event).change_context(Error::EventDecoding {
                block: block_results.height,
            })
        })
        .collect();

    iter::once(Ok(Event::BlockBegin(block_results.height)))
        .chain(events)
        .chain(iter::once(Ok(Event::BlockEnd(block_results.height))))
        .collect()
}

pin_project! {
    struct StrictlyIncreasing<S>
    where
        S: TryStream,
    {
        #[pin]
        stream: S,
        previous: Option<S::Ok>,
    }
}

trait StrictlyIncreasingExt: TryStream + Sized {
    /// Creates a stream that only yields values that are strictly increasing compared to previously yielded values.
    fn strictly_increasing_values(self) -> StrictlyIncreasing<Self> {
        StrictlyIncreasing {
            stream: self,
            previous: None,
        }
    }
}

impl<S> StrictlyIncreasingExt for S where S: TryStream {}

impl<S> Stream for StrictlyIncreasing<S>
where
    S: TryStream,
    S::Ok: Clone + PartialEq + PartialOrd,
{
    type Item = core::result::Result<S::Ok, S::Error>;
    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<core::result::Result<S::Ok, S::Error>>> {
        let mut me = self.as_mut().project();

        // loop until we get an element that is not a duplicate of an already streamed one.
        // We use loop instead of recursion here, because in the case of a stuck chain,
        // the stream could receive the same element for a long time, which would cause a stack overflow.
        loop {
            match me.stream.as_mut().try_poll_next(cx) {
                Poll::Ready(Some(Ok(current))) => {
                    let previous = me.previous.replace(current.clone());

                    match previous {
                        Some(previous) if previous >= current => {
                            me.previous.replace(previous.clone()); // revert update of the previous value
                            continue;
                        }
                        _ => return Poll::Ready(Some(Ok(current))),
                    }
                }
                poll_result => return poll_result,
            }
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
    use std::time::Duration;

    use axelar_wasm_std::err_contains;
    use error_stack::report;
    use events::Event;
    use futures::{stream, StreamExt};
    use tendermint::abci::EventAttribute;
    use tendermint::block;

    use super::super::tests::{block_results_response, random_event};
    use crate::asyncutil::future::RetryPolicy;
    use crate::event_sub::stream::{blocks, events};
    use crate::event_sub::Error;
    use crate::tm_client::{self, MockTmClient, TmClient};

    #[tokio::test(start_paused = true)]
    async fn blocks_stream_adheres_to_poll_interval_to_get_new_blocks() {
        let base_block: tendermint::Block =
            serde_json::from_str(include_str!("../tests/axelar_block.json")).unwrap();
        let mut tm_client = MockTmClient::new();
        let mut call_count = 0u64;
        let start_height = 100u64;

        tm_client.expect_latest_block().returning(move || {
            call_count += 1;
            let height = start_height + call_count - 1;
            Ok(create_block_with_height(&base_block, height))
        });

        let poll_interval = Duration::from_secs(60); // much larger than the stream delay
        let stream_delay = Duration::from_millis(100);
        let start_time = tokio::time::Instant::now();

        let stream = blocks(&tm_client, poll_interval, stream_delay);
        let results: Vec<_> = stream.take(5).collect().await;

        let elapsed = start_time.elapsed();
        let expected_min_time = poll_interval * 4; // 4 intervals between 5 blocks

        assert!(elapsed >= expected_min_time);
        assert_eq!(results.len(), 5);

        for (i, height_result) in results.into_iter().enumerate() {
            assert_eq!(height_result.unwrap().value(), start_height + i as u64);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn blocks_stream_respects_stream_delay() {
        let base_block: tendermint::Block =
            serde_json::from_str(include_str!("../tests/axelar_block.json")).unwrap();
        let mut tm_client = MockTmClient::new();
        let mut call_count = 0u64;
        let start_height = 200u64;

        tm_client.expect_latest_block().returning(move || {
            call_count += 1;
            let height = start_height + call_count - 1;
            Ok(create_block_with_height(&base_block, height))
        });

        let poll_interval = Duration::from_secs(1);
        let stream_delay = Duration::from_secs(60); // much larger than the poll interval
        let start_time = tokio::time::Instant::now();

        let stream = blocks(&tm_client, poll_interval, stream_delay);
        let results: Vec<_> = stream.take(3).collect().await;

        let elapsed = start_time.elapsed();
        let expected_min_time = stream_delay * 3; // Each block delayed by 1 minute

        assert!(elapsed >= expected_min_time);
        assert_eq!(results.len(), 3);

        for (i, height_result) in results.into_iter().enumerate() {
            assert_eq!(height_result.unwrap().value(), start_height + i as u64);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn blocks_stream_fills_gaps_in_block_sequence() {
        let base_block: tendermint::Block =
            serde_json::from_str(include_str!("../tests/axelar_block.json")).unwrap();
        let mut tm_client = MockTmClient::new();
        let mut call_count = 0u64;
        let start_height = 300u64;

        tm_client.expect_latest_block().returning(move || {
            call_count += 1;
            let height = match call_count {
                1 => start_height,
                2 => start_height + 5, // Gap: returns block 305 after 300
                3 => start_height + 8, // Gap: returns block 308 after 305
                _ => start_height + 8 + call_count - 3,
            };
            Ok(create_block_with_height(&base_block, height))
        });

        let poll_interval = Duration::from_millis(100);
        let stream_delay = Duration::from_millis(10);

        let stream = blocks(&tm_client, poll_interval, stream_delay);
        let results: Vec<_> = stream.take(12).collect().await; // Should get 300-311

        assert_eq!(results.len(), 12);

        for (i, height_result) in results.into_iter().enumerate() {
            assert_eq!(height_result.unwrap().value(), start_height + i as u64);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn blocks_stream_ignores_duplicate_blocks() {
        let base_block: tendermint::Block =
            serde_json::from_str(include_str!("../tests/axelar_block.json")).unwrap();
        let mut tm_client = MockTmClient::new();
        let mut call_count = 0u64;
        let start_height = 400u64;

        tm_client.expect_latest_block().returning(move || {
            call_count += 1;
            let height = match call_count {
                1 => start_height,     // 400
                2 => start_height + 1, // 401
                3 => start_height + 1, // 401 - immediate duplicate
                4 => start_height + 2, // 402
                5 => start_height + 1, // 401 - duplicate, older than predecessor
                6 => start_height + 2, // 402 - duplicate of already streamed
                7 => start_height - 1, // 399 - older than any streamed block
                8 => start_height + 3, // 403 - new block
                9 => start_height,     // 400 - duplicate of first streamed
                _ => start_height + 3 + call_count - 9,
            };
            Ok(create_block_with_height(&base_block, height))
        });

        let poll_interval = Duration::from_millis(100);
        let stream_delay = Duration::from_millis(10);

        let stream = blocks(&tm_client, poll_interval, stream_delay);
        let results: Vec<_> = stream.take(10).collect().await; // Should get 400, 401, 402, 403, 404, 405, 406, 407, 408, 409

        assert_eq!(results.len(), 10);

        for (i, height_result) in results.into_iter().enumerate() {
            assert_eq!(height_result.unwrap().value(), start_height + i as u64);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn blocks_stream_handles_intermittent_errors_with_gaps() {
        let base_block: tendermint::Block =
            serde_json::from_str(include_str!("../tests/axelar_block.json")).unwrap();
        let mut tm_client = MockTmClient::new();
        let mut call_count = 0u64;
        let start_height = 500u64;

        tm_client.expect_latest_block().returning(move || {
            call_count += 1;
            match call_count {
                1 => Err(report!(tendermint_rpc::Error::server(
                    "error 1".to_string()
                ))), // Start with error
                2 => Ok(create_block_with_height(&base_block, start_height)),
                3 => Err(report!(tendermint_rpc::Error::server(
                    "error 2".to_string()
                ))),
                4 => Ok(create_block_with_height(&base_block, start_height + 3)), // Gap
                5 => Err(report!(tendermint_rpc::Error::server(
                    "error 3".to_string()
                ))),
                6 => Err(report!(tendermint_rpc::Error::server(
                    "error 4".to_string()
                ))), // Consecutive errors
                7 => Err(report!(tendermint_rpc::Error::server(
                    "error 5".to_string()
                ))), // Consecutive errors
                8 => Ok(create_block_with_height(&base_block, start_height + 6)), // Another gap
                _ => Ok(create_block_with_height(
                    &base_block,
                    start_height + 6 + call_count - 8,
                )),
            }
        });

        let poll_interval = Duration::from_millis(100);
        let stream_delay = Duration::from_millis(10);

        let stream = blocks(&tm_client, poll_interval, stream_delay);
        let results: Vec<_> = stream.take(12).collect().await;

        let mut error_count = 0;
        let mut success_count = 0;
        let mut last_successful_height = start_height - 1;

        for height_result in results {
            match height_result {
                Ok(height) => {
                    success_count += 1;
                    assert_eq!(height.value(), last_successful_height + 1);
                    last_successful_height = height.value();
                }
                Err(err) => {
                    error_count += 1;
                    assert!(err_contains!(err, Error, Error::LatestBlockQuery));
                }
            }
        }

        assert_eq!(error_count, 5); // 5 errors total
        assert_eq!(success_count, 7); // 7 successful block heights
    }

    #[tokio::test(start_paused = true)]
    async fn blocks_stream_gap_filling_blocks_have_no_delay() {
        let base_block: tendermint::Block =
            serde_json::from_str(include_str!("../tests/axelar_block.json")).unwrap();
        let mut tm_client = MockTmClient::new();
        let mut call_count = 0u64;
        let start_height = 600u64;

        tm_client.expect_latest_block().returning(move || {
            call_count += 1;
            let height = match call_count {
                1 => start_height,
                2 => start_height + 5, // Creates gap, will trigger gap filling
                _ => start_height + 5, // Keep returning same to not advance further
            };

            Ok(create_block_with_height(&base_block, height))
        });

        let poll_interval = Duration::from_millis(100);
        let stream_delay = Duration::from_secs(10); // Very long delay to test gap filling has no delay
        let start_time = tokio::time::Instant::now();

        let stream = blocks(&tm_client, poll_interval, stream_delay);
        let results: Vec<_> = stream.take(6).collect().await; // Should get 600-605

        let elapsed = start_time.elapsed();

        // First block should be delayed, but gap-filling blocks (601-605) should not be delayed
        // So total time should be much less than 6 * stream_delay
        let max_expected_time = stream_delay * 2 + Duration::from_millis(100); // Only first block + block after gap + some buffer
        assert!(elapsed < max_expected_time);

        assert_eq!(results.len(), 6);
        for (i, height_result) in results.into_iter().enumerate() {
            assert_eq!(height_result.unwrap().value(), start_height + i as u64);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn events_stream_single_block_with_all_event_types() {
        let mut tm_client = MockTmClient::new();

        tm_client
            .expect_block_results()
            .times(1)
            .returning(|height| {
                Ok(block_results_response(
                    height,
                    vec![random_event()], // begin_block_events
                    vec![random_event()], // tx_events
                    vec![random_event()], // end_block_events
                ))
            });

        let retry_policy = RetryPolicy::RepeatConstant {
            sleep: Duration::from_millis(100),
            max_attempts: 3,
        };
        let block_stream = stream::iter(vec![Ok(block::Height::from(100u32))]);
        let events: Vec<_> = events(&tm_client, block_stream, retry_policy)
            .collect()
            .await;

        assert_eq!(events.len(), 5); // BlockBegin + 3 ABCI events + BlockEnd
        assert!(matches!(events[0], Ok(Event::BlockBegin(_))));
        assert!(matches!(events[1], Ok(Event::Abci { .. })));
        assert!(matches!(events[2], Ok(Event::Abci { .. })));
        assert!(matches!(events[3], Ok(Event::Abci { .. })));
        assert!(matches!(events[4], Ok(Event::BlockEnd(_))));
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::cast_possible_truncation)]
    async fn events_stream_multiple_blocks_sequentially() {
        let mut tm_client = MockTmClient::new();

        tm_client
            .expect_block_results()
            .times(3)
            .returning(|height| {
                let event_count = height.value() as usize; // Different event counts per block
                Ok(block_results_response(
                    height,
                    vec![random_event(); event_count],
                    vec![random_event(); event_count],
                    vec![random_event(); event_count],
                ))
            });

        let retry_policy = RetryPolicy::RepeatConstant {
            sleep: Duration::from_secs(10),
            max_attempts: 3,
        };
        let start_time = tokio::time::Instant::now();
        let block_stream = stream::iter(vec![
            Ok(block::Height::from(1u32)),
            Ok(block::Height::from(2u32)),
            Ok(block::Height::from(3u32)),
        ]);
        let events: Vec<_> = events(&tm_client, block_stream, retry_policy)
            .collect()
            .await;

        let elapsed = start_time.elapsed();
        assert!(elapsed < Duration::from_secs(10)); // Should complete without retries

        // Block 1: BlockBegin + 3 ABCI + BlockEnd = 5 events
        // Block 2: BlockBegin + 6 ABCI + BlockEnd = 8 events
        // Block 3: BlockBegin + 9 ABCI + BlockEnd = 11 events
        assert_eq!(events.len(), 24);

        let mut event_idx = 0;
        for block_height in 1..=3 {
            assert!(matches!(events[event_idx], Ok(Event::BlockBegin(_))));
            event_idx += 1;

            for _ in 0..(block_height * 3) {
                assert!(matches!(events[event_idx], Ok(Event::Abci { .. })));
                event_idx += 1;
            }

            assert!(matches!(events[event_idx], Ok(Event::BlockEnd(_))));
            event_idx += 1;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn events_stream_adheres_to_retry_policy_on_block_results_failure() {
        let mut tm_client = MockTmClient::new();
        let mut call_count = 0;

        tm_client
            .expect_block_results()
            .times(3)
            .returning(move |height| {
                call_count += 1;
                match call_count {
                    1 | 2 => Err(report!(tendermint_rpc::Error::server(
                        "temporary error".to_string()
                    ))),
                    3 => Ok(block_results_response(
                        height,
                        vec![random_event()],
                        vec![],
                        vec![],
                    )),
                    _ => unreachable!(),
                }
            });

        let retry_policy = RetryPolicy::RepeatConstant {
            sleep: Duration::from_secs(1),
            max_attempts: 3,
        };
        let start_time = tokio::time::Instant::now();
        let block_stream = stream::iter(vec![Ok(block::Height::from(100u32))]);
        let events: Vec<_> = events(&tm_client, block_stream, retry_policy)
            .collect()
            .await;

        let elapsed = start_time.elapsed();
        assert!(elapsed >= Duration::from_secs(2)); // 2 retries with 1 second each

        assert_eq!(events.len(), 3); // BlockBegin + 1 ABCI + BlockEnd
        assert!(events.iter().all(Result::is_ok));
    }

    #[tokio::test(start_paused = true)]
    async fn events_stream_propagates_block_height_errors() {
        let mut tm_client = MockTmClient::new();

        tm_client
            .expect_block_results()
            .times(2)
            .returning(move |height| {
                Ok(block_results_response(
                    height,
                    vec![random_event()],
                    vec![random_event()],
                    vec![random_event()],
                ))
            });

        let retry_policy = RetryPolicy::RepeatConstant {
            sleep: Duration::from_millis(100),
            max_attempts: 3,
        };
        let block_stream = stream::iter(vec![
            Ok(block::Height::from(100u32)),
            Err(report!(Error::LatestBlockQuery)),
            Ok(block::Height::from(101u32)),
        ]);
        let events: Vec<_> = events(&tm_client, block_stream, retry_policy)
            .collect()
            .await;

        assert_eq!(events.len(), 11); // Block 100: 5 events + error + Block 101: 5 events

        // First block (100) should be processed successfully
        assert!(matches!(events[0], Ok(Event::BlockBegin(_))));
        assert!(matches!(events[1], Ok(Event::Abci { .. })));
        assert!(matches!(events[2], Ok(Event::Abci { .. })));
        assert!(matches!(events[3], Ok(Event::Abci { .. })));
        assert!(matches!(events[4], Ok(Event::BlockEnd(_))));

        // Error should be propagated
        assert!(events[5].is_err());
        assert!(err_contains!(
            events[5].as_ref().unwrap_err(),
            Error,
            Error::LatestBlockQuery
        ));

        // Second block (101) should be processed successfully
        assert!(matches!(events[6], Ok(Event::BlockBegin(_))));
        assert!(matches!(events[7], Ok(Event::Abci { .. })));
        assert!(matches!(events[8], Ok(Event::Abci { .. })));
        assert!(matches!(events[9], Ok(Event::Abci { .. })));
        assert!(matches!(events[10], Ok(Event::BlockEnd(_))));
    }

    #[tokio::test(start_paused = true)]
    async fn events_stream_handles_individual_event_decoding_failures() {
        let mut tm_client = MockTmClient::new();

        tm_client
            .expect_block_results()
            .times(1)
            .returning(|height| {
                let mut invalid_event = random_event();
                invalid_event.attributes = vec![EventAttribute {
                    key: "invalid".to_string(),
                    value: "invalid".to_string(),
                    index: false,
                }]; // attributes are expected to be base64 encoded

                Ok(block_results_response(
                    height,
                    vec![random_event().clone()],
                    vec![invalid_event, random_event().clone()],
                    vec![random_event()],
                ))
            });

        let retry_policy = RetryPolicy::RepeatConstant {
            sleep: Duration::from_millis(100),
            max_attempts: 3,
        };
        let block_stream = stream::iter(vec![Ok(block::Height::from(100u32))]);
        let events: Vec<_> = events(&tm_client, block_stream, retry_policy)
            .collect()
            .await;

        assert_eq!(events.len(), 6); // BlockBegin + 4 events (1 failure, 3 success) + BlockEnd
        assert!(matches!(events[0], Ok(Event::BlockBegin(_))));
        assert!(matches!(events[1], Ok(Event::Abci { .. }))); // valid begin_block event
        assert!(matches!(events[2], Ok(Event::Abci { .. }))); // valid tx event
        assert!(events[3].is_err()); // invalid end_block event
        assert!(matches!(events[4], Ok(Event::Abci { .. }))); // valid end_block event
        assert!(matches!(events[5], Ok(Event::BlockEnd(_))));
    }

    #[tokio::test(start_paused = true)]
    async fn events_stream_maintains_buffered_processing_order() {
        let mut tm_client = MockTmClient::new();

        tm_client
            .expect_block_results()
            .times(5)
            .returning(move |height| {
                Ok(block_results_response(
                    height,
                    vec![random_event()],
                    vec![],
                    vec![],
                ))
            });

        let tm_client = SlowClient::new(tm_client, |count| {
            match count {
                1 => Duration::from_millis(500), // Slowest
                2 => Duration::from_millis(100), // Fastest
                3 => Duration::from_millis(300), // Medium
                4 => Duration::from_millis(200), // Fast
                5 => Duration::from_millis(400), // Slow
                _ => unreachable!(),
            }
        });

        let retry_policy = RetryPolicy::RepeatConstant {
            sleep: Duration::from_millis(10),
            max_attempts: 1,
        };
        let block_stream = stream::iter(vec![
            Ok(block::Height::from(1u32)),
            Ok(block::Height::from(2u32)),
            Ok(block::Height::from(3u32)),
            Ok(block::Height::from(4u32)),
            Ok(block::Height::from(5u32)),
        ]);
        let events: Vec<_> = events(&tm_client, block_stream, retry_policy)
            .collect()
            .await;

        // Events should still be in order despite different processing times
        let mut expected_block = 1u64;
        let mut event_idx = 0;

        while event_idx < events.len() {
            if let Ok(Event::BlockBegin(height)) = &events[event_idx] {
                assert_eq!(height.value(), expected_block);
                expected_block += 1;
            }
            event_idx += 1;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn events_stream_handles_empty_blocks() {
        let mut tm_client = MockTmClient::new();

        tm_client
            .expect_block_results()
            .times(3)
            .returning(|height| {
                match height.value() {
                    1 => Ok(block_results_response(height, vec![], vec![], vec![])), // Empty block
                    2 => Ok(block_results_response(
                        height,
                        vec![random_event()],
                        vec![],
                        vec![],
                    )), // One event
                    3 => Ok(block_results_response(height, vec![], vec![], vec![])), // Empty block
                    _ => unreachable!(),
                }
            });

        let retry_policy = RetryPolicy::RepeatConstant {
            sleep: Duration::from_millis(100),
            max_attempts: 3,
        };
        let block_stream = stream::iter(vec![
            Ok(block::Height::from(1u32)),
            Ok(block::Height::from(2u32)),
            Ok(block::Height::from(3u32)),
        ]);
        let events: Vec<_> = events(&tm_client, block_stream, retry_policy)
            .collect()
            .await;

        assert_eq!(events.len(), 7); // 3 BlockBegin + 1 ABCI + 3 BlockEnd

        // Block 1: empty
        assert!(matches!(events[0], Ok(Event::BlockBegin(_))));
        assert!(matches!(events[1], Ok(Event::BlockEnd(_))));

        // Block 2: one event
        assert!(matches!(events[2], Ok(Event::BlockBegin(_))));
        assert!(matches!(events[3], Ok(Event::Abci { .. })));
        assert!(matches!(events[4], Ok(Event::BlockEnd(_))));

        // Block 3: empty
        assert!(matches!(events[5], Ok(Event::BlockBegin(_))));
        assert!(matches!(events[6], Ok(Event::BlockEnd(_))));
    }

    #[tokio::test(start_paused = true)]
    async fn events_stream_exhausted_retry_attempts() {
        let mut tm_client = MockTmClient::new();

        tm_client
            .expect_block_results()
            .times(3)
            .returning(|_height| {
                Err(report!(tendermint_rpc::Error::server(
                    "persistent error".to_string()
                )))
            });

        let retry_policy = RetryPolicy::RepeatConstant {
            sleep: Duration::from_secs(1),
            max_attempts: 3,
        };
        let start_time = tokio::time::Instant::now();
        let block_stream = stream::iter(vec![Ok(block::Height::from(100u32))]);
        let events: Vec<_> = events(&tm_client, block_stream, retry_policy)
            .collect()
            .await;

        let elapsed = start_time.elapsed();
        assert!(elapsed >= Duration::from_secs(2)); // 2 retries with 1 second each

        assert_eq!(events.len(), 1);
        assert!(events[0].is_err());
        assert!(err_contains!(
            events[0].as_ref().unwrap_err(),
            Error,
            Error::BlockResultsQuery { block: _ }
        ));
    }

    struct SlowClient<T, DelayFn>
    where
        T: TmClient,
        DelayFn: Fn(u64) -> Duration + Send + Sync,
    {
        client: T,
        delay: DelayFn,
        call_count: std::sync::atomic::AtomicU64,
    }

    impl<T, DelayFn> SlowClient<T, DelayFn>
    where
        T: TmClient + Send + Sync,
        DelayFn: Fn(u64) -> Duration + Send + Sync,
    {
        pub fn new(client: T, delay: DelayFn) -> Self {
            Self {
                client,
                delay,
                call_count: std::sync::atomic::AtomicU64::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl<T, DelayFn> TmClient for SlowClient<T, DelayFn>
    where
        T: TmClient + Send + Sync,
        DelayFn: Fn(u64) -> Duration + Send + Sync,
    {
        async fn latest_block(
            &self,
        ) -> error_stack::Result<tm_client::BlockResponse, tm_client::Error> {
            self.call_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let count = self.call_count.load(std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep((self.delay)(count)).await; // Simulate slow response
            self.client.latest_block().await
        }

        async fn block_results(
            &self,
            height: block::Height,
        ) -> error_stack::Result<tm_client::BlockResultsResponse, tm_client::Error> {
            self.call_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let count = self.call_count.load(std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep((self.delay)(count)).await; // Simulate slow response
            self.client.block_results(height).await
        }
    }

    fn create_block_with_height(
        base_block: &tendermint::Block,
        height: u64,
    ) -> tm_client::BlockResponse {
        let mut block = base_block.clone();
        block.header.height = height.try_into().unwrap();
        tm_client::BlockResponse {
            block_id: Default::default(),
            block,
        }
    }
}
