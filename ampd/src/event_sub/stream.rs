use std::iter;
use std::time::Duration;

use error_stack::ResultExt;
use events::Event;
use futures::{stream, FutureExt, Stream, StreamExt};
use tendermint::block;
use tokio::time::{interval, Interval};
use tokio_util::sync::CancellationToken;

use crate::asyncutil::future::{with_retry, RetryPolicy};
use crate::tm_client::TmClient;

type Error = super::Error;
type Result<T> = error_stack::Result<T, Error>;

pub async fn blocks<T>(
    tm_client: &T,
    poll_interval: Duration,
    token: CancellationToken,
) -> Result<impl Stream<Item = Result<block::Height>> + '_>
where
    T: TmClient,
{
    latest_block_height(tm_client)
        .await
        .map(BlockState::new)
        .map(|block_state| block_state.stream(tm_client, interval(poll_interval), token))
        .map(Box::pin)
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
        .map(move |block_height| process_block(tm_client, block_height, retry_policy))
        .buffered(super::BLOCK_PROCESSING_BUFFER)
        .flat_map(|result| {
            result.map_or_else(
                |err| stream::iter(vec![Err(err)]),
                |events| stream::iter(events.into_iter().map(Ok).collect::<Vec<_>>()),
            )
        })
}

async fn process_block<T>(
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

#[derive(Copy, Clone)]
struct BlockState {
    next_to_stream: block::Height,
    latest: block::Height,
}

impl BlockState {
    fn new(latest: block::Height) -> Self {
        Self {
            next_to_stream: latest,
            latest,
        }
    }

    async fn update<T>(
        mut self,
        tm_client: &T,
        interval: &mut Interval,
        token: &CancellationToken,
    ) -> Result<Option<Self>>
    where
        T: TmClient,
    {
        while !token.is_cancelled() && self.next_to_stream > self.latest {
            self.latest = interval
                .tick()
                .then(|_| latest_block_height(tm_client))
                .await?;
        }

        match token.is_cancelled() {
            true => Ok(None),
            false => {
                self.next_to_stream = self.next_to_stream.increment();
                Ok(Some(self))
            }
        }
    }

    fn stream<T>(
        self,
        tm_client: &T,
        interval: Interval,
        token: CancellationToken,
    ) -> impl Stream<Item = Result<block::Height>> + '_
    where
        T: TmClient,
    {
        futures::stream::unfold(
            (self, tm_client, interval, token),
            |(block_state, tm_client, mut interval, token)| async move {
                let to_stream = block_state.next_to_stream;

                match block_state.update(tm_client, &mut interval, &token).await {
                    Ok(None) => None,
                    Ok(Some(block_state)) => {
                        Some((Ok(to_stream), (block_state, tm_client, interval, token)))
                    }
                    Err(err) => Some((Err(err), (block_state, tm_client, interval, token))),
                }
            },
        )
    }
}

async fn latest_block_height<T: TmClient>(tm_client: &T) -> Result<block::Height> {
    tm_client
        .latest_block()
        .await
        .change_context(Error::LatestBlockQuery)
        .map(|res| res.block.header().height)
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::assert_err_contains;
    use error_stack::report;
    use futures::StreamExt;
    use tendermint::abci;

    use super::super::tests::{block_results_response, random_event};
    use super::*;
    use crate::tm_client::{self, MockTmClient};

    #[tokio::test]
    async fn event_stream_should_stream_error_if_block_stream_streams_error() {
        let tm_client = MockTmClient::new();

        let retry_policy = RetryPolicy::RepeatConstant {
            sleep: Duration::from_millis(100),
            max_attempts: 3,
        };
        let block_stream = stream::iter(vec![
            Err(report!(Error::LatestBlockQuery)),
            Err(report!(Error::LatestBlockQuery)),
            Err(report!(Error::LatestBlockQuery)),
        ]);
        let mut stream = events(&tm_client, block_stream, retry_policy);

        assert_err_contains!(stream.next().await.unwrap(), Error, Error::LatestBlockQuery);
        assert_err_contains!(stream.next().await.unwrap(), Error, Error::LatestBlockQuery);
        assert_err_contains!(stream.next().await.unwrap(), Error, Error::LatestBlockQuery);
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn event_stream_should_retry_events_retrieval() {
        let mut tm_client = MockTmClient::new();
        let mut block_height_1_call_count = 0;
        let mut block_height_2_call_count = 0;
        tm_client
            .expect_block_results()
            .times(6)
            .returning(move |height| {
                if height == 1u32.into() {
                    block_height_1_call_count += 1;

                    match block_height_1_call_count {
                        1 => Err(report!(tendermint_rpc::Error::server(
                            "server error".to_string()
                        ))),
                        2 => {
                            let mut invalid_event = random_event();
                            invalid_event.attributes = vec![abci::EventAttribute {
                                key: "???".to_string(),
                                value: "!!!".to_string(),
                                index: false,
                            }];

                            Ok(block_results_response(
                                height,
                                vec![],
                                vec![],
                                vec![invalid_event],
                            ))
                        }
                        3 => Ok(block_results_response(
                            height,
                            vec![random_event()],
                            vec![random_event()],
                            vec![random_event()],
                        )),
                        _ => unreachable!(),
                    }
                } else if height == 2u32.into() {
                    block_height_2_call_count += 1;

                    match block_height_2_call_count {
                        1 | 3 => Err(report!(tendermint_rpc::Error::server(
                            "server error".to_string()
                        ))),
                        2 => {
                            let mut invalid_event = random_event();
                            invalid_event.attributes = vec![abci::EventAttribute {
                                key: "???".to_string(),
                                value: "!!!".to_string(),
                                index: false,
                            }];

                            Ok(block_results_response(
                                height,
                                vec![],
                                vec![],
                                vec![invalid_event],
                            ))
                        }
                        _ => unreachable!(),
                    }
                } else {
                    unreachable!()
                }
            });

        let retry_policy = RetryPolicy::RepeatConstant {
            sleep: Duration::from_millis(100),
            max_attempts: 3,
        };
        let block_stream = stream::iter(vec![Ok(1u32.into()), Ok(2u32.into())]);
        let mut stream = events(&tm_client, block_stream, retry_policy);

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
        assert_err_contains!(
            stream.next().await.unwrap(),
            Error,
            Error::BlockResultsQuery { .. }
        );
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
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

    #[tokio::test]
    async fn block_stream_should_return_error_immediately_if_latest_block_height_query_fails() {
        let interval = std::time::Duration::from_millis(100);

        let mut tm_client = MockTmClient::new();
        tm_client.expect_latest_block().return_once(|| {
            Err(report!(tendermint_rpc::Error::server(
                "server error".to_string()
            )))
        });

        assert!(blocks(&tm_client, interval, CancellationToken::new())
            .await
            .is_err());
    }

    #[tokio::test]
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
            let mut stream = blocks(&tm_client, interval, child_token).await.unwrap();

            while stream.next().await.is_some() {}
        });

        token.cancel();
        assert!(handle.await.is_ok());
    }

    #[tokio::test]
    async fn block_stream_should_stream_error_if_subsequent_latest_block_height_query_fails() {
        let block: tendermint::Block =
            serde_json::from_str(include_str!("../tests/axelar_block.json")).unwrap();
        let height = block.header().height;
        let interval = std::time::Duration::from_millis(100);

        let mut tm_client = MockTmClient::new();
        let mut call_count = 0;
        tm_client.expect_latest_block().times(3).returning(move || {
            call_count += 1;

            match call_count {
                1 => Ok(tm_client::BlockResponse {
                    block_id: Default::default(),
                    block: block.clone(),
                }),
                2 | 3 => Err(report!(tendermint_rpc::Error::server(
                    "server error".to_string()
                ))),
                _ => unreachable!(),
            }
        });

        let token = CancellationToken::new();
        let mut stream = blocks(&tm_client, interval, token.child_token())
            .await
            .unwrap();

        assert_eq!(stream.next().await.unwrap().unwrap(), height);
        assert_err_contains!(stream.next().await.unwrap(), Error, Error::LatestBlockQuery);
        assert_err_contains!(stream.next().await.unwrap(), Error, Error::LatestBlockQuery);

        token.cancel();
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn block_stream_should_stream_block_height() {
        let block: tendermint::Block =
            serde_json::from_str(include_str!("../tests/axelar_block.json")).unwrap();
        let height = block.header().height;
        let interval = std::time::Duration::from_millis(100);

        let mut tm_client = MockTmClient::new();
        let mut call_count = 0;
        tm_client.expect_latest_block().times(4).returning(move || {
            let mut block = block.clone();
            call_count += 1;

            match call_count {
                1 => Ok(tm_client::BlockResponse {
                    block_id: Default::default(),
                    block,
                }),
                2 => {
                    block.header.height = (block.header().height.value() + 3).try_into().unwrap();

                    Ok(tm_client::BlockResponse {
                        block_id: Default::default(),
                        block,
                    })
                }
                3 => Err(report!(tendermint_rpc::Error::server(
                    "server error".to_string()
                ))),
                4 => {
                    block.header.height = (block.header().height.value() + 6).try_into().unwrap();

                    Ok(tm_client::BlockResponse {
                        block_id: Default::default(),
                        block,
                    })
                }
                _ => unreachable!(),
            }
        });

        let token = CancellationToken::new();
        let mut stream = blocks(&tm_client, interval, token.child_token())
            .await
            .unwrap();

        assert_eq!(stream.next().await.unwrap().unwrap(), height);
        let height = height.increment();
        assert_eq!(stream.next().await.unwrap().unwrap(), height);
        let height = height.increment();
        assert_eq!(stream.next().await.unwrap().unwrap(), height);
        let height = height.increment();
        assert_eq!(stream.next().await.unwrap().unwrap(), height);

        assert_err_contains!(stream.next().await.unwrap(), Error, Error::LatestBlockQuery);

        let height = height.increment();
        assert_eq!(stream.next().await.unwrap().unwrap(), height);
        let height = height.increment();
        assert_eq!(stream.next().await.unwrap().unwrap(), height);
        let height = height.increment();
        assert_eq!(stream.next().await.unwrap().unwrap(), height);

        token.cancel();
        assert!(stream.next().await.is_none());
    }
}
