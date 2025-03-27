use std::iter;
use std::time::Duration;

use axelar_wasm_std::FnExt;
use error_stack::ResultExt;
use events::Event;
use futures::{stream, Stream, StreamExt};
use tendermint::block;
use tokio::time::{interval, Interval};

use crate::tm_client::TmClient;

type Error = super::Error;
type Result<T> = error_stack::Result<T, Error>;

pub async fn event_stream<'a, T, F>(
    tm_client: &'a T,
    poll_interval: Duration,
    capacity: usize,
    skip_block_fn: F,
) -> Result<impl Stream<Item = Result<Event>> + 'a>
where
    T: TmClient,
    F: Fn() -> bool + Copy + 'a,
{
    Ok(block_stream(tm_client, poll_interval)
        .await?
        .map(move |block_height| process_block(tm_client, block_height, skip_block_fn))
        .buffered(capacity)
        .flat_map(|result| {
            result.map_or_else(
                |err| stream::iter(vec![Err(err)]),
                |events| stream::iter(events.into_iter().map(Ok).collect::<Vec<_>>()),
            )
        }))
}

async fn process_block<T>(
    tm_client: &T,
    block_height: Result<block::Height>,
    skip_block_fn: impl Fn() -> bool,
) -> Result<Vec<Event>>
where
    T: TmClient,
{
    match (skip_block_fn(), block_height) {
        (true, _) => Ok(vec![]),
        (_, Ok(block_height)) => events(tm_client, block_height).await,
        (_, Err(err)) => Err(err),
    }
}

async fn block_stream<'a, T>(
    tm_client: &'a T,
    poll_interval: Duration,
) -> Result<impl Stream<Item = Result<block::Height>> + 'a>
where
    T: TmClient,
{
    latest_block_height(tm_client)
        .await
        .map(|latest| BlockState {
            current: latest,
            latest,
        })
        .map(|block_state| block_state.stream(tm_client, interval(poll_interval)))
        .map(Box::pin)
}

async fn events<T>(tm_client: &T, block_height: block::Height) -> Result<Vec<Event>>
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
    current: block::Height,
    latest: block::Height,
}

impl BlockState {
    async fn update<T>(mut self, tm_client: &T, interval: &mut Interval) -> Result<Self>
    where
        T: TmClient,
    {
        while self.current > self.latest {
            self.latest = interval
                .tick()
                .then(|_| latest_block_height(tm_client))
                .await?;
        }

        self.current = self.current.increment();

        Ok(self)
    }

    fn stream<'a, T>(
        self,
        tm_client: &'a T,
        interval: Interval,
    ) -> impl Stream<Item = Result<block::Height>> + 'a
    where
        T: TmClient,
    {
        futures::stream::unfold(
            (self, tm_client, interval),
            |(block_state, tm_client, mut interval)| async move {
                let current = block_state.current;

                match block_state.update(tm_client, &mut interval).await {
                    Ok(block_state) => Some((Ok(current), (block_state, tm_client, interval))),
                    Err(err) => Some((Err(err), (block_state, tm_client, interval))),
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
    use tendermint_rpc::endpoint::block::Response;

    use super::*;
    use crate::tm_client::MockTmClient;

    #[tokio::test]
    async fn block_stream_should_return_error_immediately_if_latest_block_height_query_fails() {
        let interval = std::time::Duration::from_secs(1);

        let mut tm_client = MockTmClient::new();
        tm_client.expect_latest_block().return_once(|| {
            Err(report!(tendermint_rpc::Error::server(
                "server error".to_string()
            )))
        });

        assert!(block_stream(&tm_client, interval).await.is_err());
    }

    #[tokio::test]
    async fn block_stream_should_stream_error_if_subsequent_latest_block_height_query_fails() {
        let block: tendermint::Block =
            serde_json::from_str(include_str!("../tests/axelar_block.json")).unwrap();
        let height = block.header().height;
        let interval = std::time::Duration::from_secs(1);

        let mut tm_client = MockTmClient::new();
        let mut call_count = 0;
        tm_client.expect_latest_block().times(3).returning(move || {
            call_count += 1;

            match call_count {
                1 => Ok(Response {
                    block_id: Default::default(),
                    block: block.clone(),
                }),
                _ => Err(report!(tendermint_rpc::Error::server(
                    "server error".to_string()
                ))),
            }
        });

        let mut stream = block_stream(&tm_client, interval).await.unwrap();

        assert_eq!(stream.next().await.unwrap().unwrap(), height);
        assert_err_contains!(stream.next().await.unwrap(), Error, Error::LatestBlockQuery);
        assert_err_contains!(stream.next().await.unwrap(), Error, Error::LatestBlockQuery);
    }

    #[tokio::test]
    async fn block_stream_should_stream_block_height() {
        let block: tendermint::Block =
            serde_json::from_str(include_str!("../tests/axelar_block.json")).unwrap();
        let height = block.header().height;
        let interval = std::time::Duration::from_secs(1);

        let mut tm_client = MockTmClient::new();
        let mut call_count = 0;
        tm_client.expect_latest_block().times(4).returning(move || {
            let mut block = block.clone();
            call_count += 1;

            match call_count {
                1 => Ok(Response {
                    block_id: Default::default(),
                    block,
                }),
                2 => {
                    block.header.height = (block.header().height.value() + 3).try_into().unwrap();

                    Ok(Response {
                        block_id: Default::default(),
                        block,
                    })
                }
                3 => Err(report!(tendermint_rpc::Error::server(
                    "server error".to_string()
                ))),
                _ => {
                    block.header.height = (block.header().height.value() + 6).try_into().unwrap();

                    Ok(Response {
                        block_id: Default::default(),
                        block,
                    })
                }
            }
        });

        let mut stream = block_stream(&tm_client, interval).await.unwrap();

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
    }
}
