use std::convert::{TryFrom, TryInto};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use error_stack::{FutureExt, Report, Result};
use error_stack::{IntoReport, ResultExt};
use tendermint::abci;
use tendermint::block;
use thiserror::Error;
use tokio::select;
use tokio::sync::broadcast::{self, Sender};
use tokio::time;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::tm_client::TmClient;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    BlockEnd(block::Height),
    Abci {
        event_type: String,
        attributes: serde_json::Map<String, serde_json::Value>,
    },
}

fn decode_event_attribute(attribute: &abci::EventAttribute) -> Result<(String, String), EventSubError> {
    Ok((
        base64_to_utf8(&attribute.key).into_report()?,
        base64_to_utf8(&attribute.value).into_report()?,
    ))
}

fn base64_to_utf8(base64_str: &str) -> std::result::Result<String, EventSubError> {
    Ok(String::from_utf8(STANDARD.decode(base64_str)?)?)
}

impl TryFrom<abci::Event> for Event {
    type Error = Report<EventSubError>;

    fn try_from(event: abci::Event) -> Result<Self, EventSubError> {
        let abci::Event {
            kind: event_type,
            attributes,
        } = event;

        let attributes = attributes
            .iter()
            .map(decode_event_attribute)
            .map(|decoded| {
                let (key, value) = decoded.change_context_lazy(|| EventSubError::DecodeEvent {
                    kind: event_type.clone(),
                })?;

                match serde_json::from_str(&value) {
                    Ok(v) => Ok((key, v)),
                    Err(_) => Ok((key, value.into())),
                }
            })
            .collect::<Result<_, _>>()?;

        Ok(Self::Abci { event_type, attributes })
    }
}

pub struct EventSub<T: TmClient + Sync> {
    client: T,
    start_from: Option<block::Height>,
    poll_interval: Duration,
    tx: Sender<Event>,
    token: CancellationToken,
}

impl<T: TmClient + Sync> EventSub<T> {
    pub fn new(client: T, capacity: usize, token: CancellationToken) -> Self {
        let (tx, _) = broadcast::channel::<Event>(capacity);

        EventSub {
            client,
            start_from: None,
            poll_interval: Duration::new(5, 0),
            tx,
            token,
        }
    }

    pub fn start_from(mut self, height: block::Height) -> Self {
        self.start_from = Some(height);
        self
    }

    #[allow(dead_code)]
    pub fn poll_interval(mut self, poll_interval: Duration) -> Self {
        self.poll_interval = poll_interval;
        self
    }

    pub fn sub(&mut self) -> impl Stream<Item = Result<Event, BroadcastStreamRecvError>> {
        BroadcastStream::new(self.tx.subscribe()).map(IntoReport::into_report)
    }

    pub async fn run(mut self) -> Result<(), EventSubError> {
        let mut curr_block_height = match self.start_from {
            Some(start_from) => start_from,
            None => self.latest_block_height().await?,
        };
        let mut interval = time::interval(self.poll_interval);

        loop {
            select! {
                _ = interval.tick() => {
                    curr_block_height = self.process_blocks_from(curr_block_height).await?.increment();
                },
                _ = self.token.cancelled() => {
                    info!("event sub exiting");

                    return Ok(())
                },
            }
        }
    }

    async fn latest_block_height(&self) -> Result<block::Height, EventSubError> {
        let res = self
            .client
            .latest_block()
            .change_context(EventSubError::RPCFailed)
            .await?;

        Ok(res.block.header().height)
    }

    // this is extracted into a function so the block height attachment can be added no matter which call fails
    async fn process_blocks_from(&mut self, from: block::Height) -> Result<block::Height, EventSubError> {
        let mut height = from;
        let to = self.latest_block_height().await?;

        while height <= to {
            self.process_block(height)
                .attach_printable(format!("{{ block_height = {height} }}"))
                .await?;

            if self.token.is_cancelled() {
                return Ok(height);
            }

            height = height.increment();
        }

        Ok(to)
    }

    async fn process_block(&self, height: block::Height) -> Result<(), EventSubError> {
        for event in self.events(height).await? {
            self.tx
                .send(event.try_into()?)
                .into_report()
                .change_context(EventSubError::PublishFailed)?;
        }
        self.tx
            .send(Event::BlockEnd(height))
            .into_report()
            .change_context(EventSubError::PublishFailed)?;

        Ok(())
    }

    async fn events(&self, block_height: block::Height) -> Result<Vec<abci::Event>, EventSubError> {
        let block_results = self
            .client
            .block_results(block_height)
            .change_context(EventSubError::EventQueryFailed { block: block_height })
            .await?;

        let begin_block_events = block_results.begin_block_events.into_iter().flatten();
        let tx_events = block_results.txs_results.into_iter().flatten().flat_map(|tx| tx.events);
        let end_block_events = block_results.end_block_events.into_iter().flatten();

        Ok(begin_block_events.chain(tx_events).chain(end_block_events).collect())
    }
}

pub fn skip_to_block(
    stream: impl Stream<Item = Result<Event, BroadcastStreamRecvError>>,
    height: block::Height,
) -> impl Stream<Item = Result<Event, BroadcastStreamRecvError>> {
    stream.skip_while(move |event| !matches!(event, Ok(Event::BlockEnd(h)) if h.increment() >= height))
}

#[derive(Error, Debug)]
pub enum EventSubError {
    #[error("querying events for block {block} failed")]
    EventQueryFailed { block: block::Height },
    #[error("failed to send events to subscribers")]
    PublishFailed,
    #[error("failed calling RPC method")]
    RPCFailed,
    #[error("failed decoding event {kind}")]
    DecodeEvent { kind: String },
    #[error("{0}")]
    Base64(#[from] base64::DecodeError),
    #[error("{0}")]
    UTF8(#[from] std::string::FromUtf8Error),
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;
    use std::time::Duration;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use futures::stream::StreamExt;
    use rand::Rng;
    use random_string::generate;
    use tendermint::{abci, AppHash};
    use tokio::test;
    use tokio_util::sync::CancellationToken;

    use crate::event_sub::{Event, EventSub};
    use crate::tm_client;

    #[test]
    async fn start_from_should_work() {
        let block_count = 10;
        let block: tendermint::Block = serde_json::from_str(include_str!("../tests/fixtures/block.json")).unwrap();
        let from_height = (block.header.height.value() - block_count + 1).try_into().unwrap();
        let to_height = block.header.height;

        let mut mock_client = tm_client::MockTmClient::new();
        mock_client.expect_latest_block().once().returning(move || {
            Ok(tm_client::BlockResponse {
                block_id: Default::default(),
                block: block.clone(),
            })
        });
        mock_client
            .expect_block_results()
            .times(block_count as usize)
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
        let event_sub = EventSub::new(mock_client, 2 * block_count as usize, token.child_token());
        let mut client = event_sub.start_from(from_height);
        let mut stream = client.sub();

        let handle = tokio::spawn(async move { client.run().await });

        for height in from_height.value()..to_height.value() {
            let event = stream.next().await;
            assert_eq!(event.unwrap().unwrap(), Event::BlockEnd(height.try_into().unwrap()));
        }

        token.cancel();

        assert!(handle.await.is_ok());
    }

    #[test]
    async fn should_start_from_latest_when_none_is_given() {
        let block: tendermint::Block = serde_json::from_str(include_str!("../tests/fixtures/block.json")).unwrap();
        let height = block.header.height;

        let mut mock_client = tm_client::MockTmClient::new();
        mock_client.expect_latest_block().times(2).returning(move || {
            Ok(tm_client::BlockResponse {
                block_id: Default::default(),
                block: block.clone(),
            })
        });
        mock_client.expect_block_results().once().returning(|height| {
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
        let mut event_sub = EventSub::new(mock_client, 10, token.child_token());
        let mut stream = event_sub.sub();

        let handle = tokio::spawn(async move { event_sub.run().await });

        let event = stream.next().await;
        assert_eq!(event.unwrap().unwrap(), Event::BlockEnd(height));

        token.cancel();

        assert!(handle.await.is_ok());
    }

    #[test]
    async fn stream_should_work() {
        let block_count = 10;
        let block: tendermint::Block = serde_json::from_str(include_str!("../tests/fixtures/block.json")).unwrap();
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
        let event_count_per_block = begin_block_events_count + tx_events_count + end_block_events + 1;

        let mut mock_client = tm_client::MockTmClient::new();
        let mut latest_block_call_count = 0;
        mock_client.expect_latest_block().times(block_count).returning(move || {
            let mut block = block.clone();
            block.header.height = (block_height.value() + latest_block_call_count).try_into().unwrap();

            latest_block_call_count += 1;
            Ok(tm_client::BlockResponse {
                block_id: Default::default(),
                block,
            })
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
        let event_sub = EventSub::new(mock_client, block_count * event_count_per_block, token.child_token());
        let mut client = event_sub
            .start_from(block_height)
            .poll_interval(Duration::new(0, 1e8 as u32));
        let mut stream = client.sub();

        let handle = tokio::spawn(async move { client.run().await });

        for i in 1..(block_count * event_count_per_block + 1) {
            let event = stream.next().await;
            match i % event_count_per_block {
                0 => {
                    assert!(matches!(event, Some(Ok(Event::BlockEnd(..)))));
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
