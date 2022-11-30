use futures::stream::StreamExt;
use std::collections::HashMap;
use tendermint::abci::Event as AbciEvent;
use tendermint_rpc::event::EventData;
use tendermint_rpc::query::EventType;
use tendermint_rpc::Error;
use tendermint_rpc::{Client, SubscriptionClient, WebSocketClient};
use tokio::sync::broadcast::{channel, Sender};
use tokio_stream::wrappers::BroadcastStream;

#[derive(Clone, Debug)]
pub struct Event {
    pub ty: String,
    pub attributes: HashMap<String, String>,
}

impl From<AbciEvent> for Event {
    fn from(event: AbciEvent) -> Self {
        Self {
            ty: event.kind,
            attributes: event
                .attributes
                .iter()
                .map(|tag| (tag.key.to_string(), tag.value.to_string()))
                .collect(),
        }
    }
}

pub struct EventSubClient {
    client: WebSocketClient,
    capacity: usize,
    tx: Option<Sender<Event>>,
}

impl EventSubClient {
    pub fn new(client: WebSocketClient, capacity: usize) -> Self {
        EventSubClient {
            client,
            capacity,
            tx: None,
        }
    }

    pub fn sub(&mut self) -> BroadcastStream<Event> {
        let rx = match &self.tx {
            None => {
                let (tx, rx) = channel::<Event>(self.capacity);
                self.tx = Some(tx);

                rx
            }
            Some(tx) => tx.subscribe(),
        };

        BroadcastStream::new(rx)
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        if self.tx.is_none() {
            return Err(Error::client_internal("no subscriber".into()));
        }

        let mut sub = self.client.subscribe(EventType::NewBlock.into()).await?;
        while let Some(res) = sub.next().await {
            let event = res?;

            if let EventData::NewBlock {
                block: Some(block),
                result_begin_block: _,
                result_end_block: _,
            } = event.data
            {
                let block_results = self.client.block_results(block.header().height).await?;

                let begin_block_events = block_results.begin_block_events.unwrap_or_default();
                let end_block_events = block_results.end_block_events.unwrap_or_default();
                let tx_events: Vec<AbciEvent> = block_results
                    .txs_results
                    .unwrap_or_default()
                    .iter()
                    .flat_map(|tx| tx.events.clone())
                    .collect();

                for event in begin_block_events
                    .iter()
                    .chain(tx_events.iter())
                    .chain(end_block_events.iter())
                {
                    self.tx
                        .as_mut()
                        .unwrap()
                        .send(event.to_owned().into())
                        .map_err(|err| Error::client_internal(err.to_string()))?;
                }
            }
        }

        Ok(())
    }
}
