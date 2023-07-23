use std::iter;
use std::time::Duration;

use async_trait::async_trait;
use cosmrs::{Any, Gas};
use error_stack::{self, Report, ResultExt};
use thiserror::Error;
use tokio::time;
use tokio::{select, sync::mpsc};

use super::msg_queue::MsgQueue;
use crate::broadcaster::{clients::BroadcastClient, Broadcaster};

type Result<T = ()> = error_stack::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed estimating fee for message")]
    EstimateFee,
    #[error("failed broadcasting messages in queue")]
    Broadcast,
}

pub struct QueuedBroadcasterDriver {
    #[allow(dead_code)]
    broadcast_tx: mpsc::Sender<()>,
}

impl QueuedBroadcasterDriver {
    #[allow(dead_code)]
    pub async fn force_broadcast(&self) -> Result {
        self.broadcast_tx
            .send(())
            .await
            .map_err(|_| Report::new(Error::Broadcast))
    }
}

#[async_trait]
pub trait BroadcasterClient {
    async fn broadcast(&self, tx: Any) -> Result;
}

pub struct QueuedBroadcasterClient {
    sender: mpsc::Sender<Any>,
}

#[async_trait]
impl BroadcasterClient for QueuedBroadcasterClient {
    async fn broadcast(&self, tx: Any) -> Result {
        self.sender.send(tx).await.map_err(|_| Report::new(Error::Broadcast))
    }
}

pub struct QueuedBroadcaster<T>
where
    T: BroadcastClient,
{
    broadcaster: Broadcaster<T>,
    queue: MsgQueue,
    batch_gas_limit: Gas,
    broadcast_interval: Duration,
    channel: (mpsc::Sender<Any>, mpsc::Receiver<Any>),
    broadcast_rx: mpsc::Receiver<()>,
}

impl<T> QueuedBroadcaster<T>
where
    T: BroadcastClient,
{
    pub fn new(
        broadcaster: Broadcaster<T>,
        batch_gas_limit: Gas,
        capacity: usize,
        broadcast_interval: Duration,
    ) -> (Self, QueuedBroadcasterDriver) {
        let (broadcast_tx, broadcast_rx) = mpsc::channel(1);

        (
            Self {
                broadcaster,
                queue: MsgQueue::default(),
                batch_gas_limit,
                broadcast_interval,
                channel: mpsc::channel(capacity),
                broadcast_rx,
            },
            QueuedBroadcasterDriver { broadcast_tx },
        )
    }

    pub async fn run(mut self) -> Result {
        let (tx, mut rx) = self.channel;
        drop(tx);

        let mut queue = self.queue;
        let mut broadcaster = self.broadcaster;

        let mut interval = time::interval(self.broadcast_interval);

        loop {
            select! {
              msg = rx.recv() => match msg {
                None => break,
                Some(msg) => {
                  let fee = broadcaster.estimate_fee(iter::once(msg.clone())).await.change_context(Error::EstimateFee)?;

                  if fee.gas_limit + queue.gas_cost() >= self.batch_gas_limit {
                    interval.reset();
                    broadcast_all(&mut queue, &mut broadcaster).await?;
                  }

                  queue.push(msg, fee.gas_limit);
                }
              },
              _ = interval.tick() => broadcast_all(&mut queue, &mut broadcaster).await?,
              _ = self.broadcast_rx.recv() => {
                interval.reset();
                broadcast_all(&mut queue, &mut broadcaster).await?;
              },
            }
        }

        broadcast_all(&mut queue, &mut broadcaster).await?;

        Ok(())
    }

    pub fn client(&self) -> QueuedBroadcasterClient {
        QueuedBroadcasterClient {
            sender: self.channel.0.clone(),
        }
    }
}

async fn broadcast_all<T>(queue: &mut MsgQueue, broadcaster: &mut Broadcaster<T>) -> Result
where
    T: BroadcastClient,
{
    let msgs = queue.pop_all();

    match msgs.len() {
        0 => Ok(()),
        _ => broadcaster
            .broadcast(msgs)
            .await
            .map(|_| ())
            .change_context(Error::Broadcast),
    }
}

#[cfg(test)]
mod test {
    use cosmos_sdk_proto::cosmos::base::abci::v1beta1::GasInfo;
    use cosmos_sdk_proto::cosmos::base::abci::v1beta1::TxResponse;
    use cosmos_sdk_proto::cosmos::tx::v1beta1::{GetTxResponse, SimulateResponse};
    use cosmos_sdk_proto::Any;
    use cosmrs::bank::MsgSend;
    use cosmrs::tx::Msg;
    use tokio::test;
    use tokio::time::{sleep, Duration};

    use super::QueuedBroadcaster;
    use crate::broadcaster::clients::MockBroadcastClient;
    use crate::broadcaster::key::ECDSASigningKey;
    use crate::broadcaster::{BroadcasterBuilder, Config};
    use crate::queue::queued_broadcaster::BroadcasterClient;
    use crate::types::TMAddress;

    #[test]
    async fn should_not_broadcast_when_gas_limit_has_not_been_reached() {
        let tx_count = 9;
        let gas_limit = 100;
        let gas_used = 10;
        let mut broadcast_client = MockBroadcastClient::new();
        broadcast_client.expect_simulate().times(tx_count).returning(move |_| {
            Ok(SimulateResponse {
                gas_info: Some(GasInfo {
                    gas_used,
                    ..Default::default()
                }),
                result: None,
            })
        });
        broadcast_client.expect_simulate().once().returning(move |_| {
            Ok(SimulateResponse {
                gas_info: Some(GasInfo {
                    gas_used: gas_used * (tx_count as u64),
                    ..Default::default()
                }),
                result: None,
            })
        });
        broadcast_client
            .expect_broadcast_tx()
            .once()
            .returning(|_| Ok(TxResponse::default()));
        broadcast_client.expect_get_tx().once().returning(|_| {
            Ok(GetTxResponse {
                tx_response: Some(TxResponse {
                    code: 0,
                    ..TxResponse::default()
                }),
                ..GetTxResponse::default()
            })
        });

        let broadcaster =
            BroadcasterBuilder::new(broadcast_client, ECDSASigningKey::random(), Config::default()).build();
        let (client, _driver) = QueuedBroadcaster::new(broadcaster, gas_limit, tx_count, Duration::from_secs(5));

        let tx = client.client();
        for _ in 0..tx_count {
            tx.broadcast(dummy_msg()).await.unwrap();
        }
        drop(tx);

        assert!(client.run().await.is_ok());
    }

    #[test]
    async fn should_broadcast_when_broadcast_interval_has_been_reached() {
        let tx_count = 9;
        let gas_limit = 100;
        let broadcast_interval = Duration::from_secs(1);
        let gas_used = 10;
        let mut broadcast_client = MockBroadcastClient::new();
        broadcast_client.expect_simulate().times(tx_count).returning(move |_| {
            Ok(SimulateResponse {
                gas_info: Some(GasInfo {
                    gas_used,
                    ..Default::default()
                }),
                result: None,
            })
        });
        broadcast_client.expect_simulate().once().returning(move |_| {
            Ok(SimulateResponse {
                gas_info: Some(GasInfo {
                    gas_used: gas_used * (tx_count as u64),
                    ..Default::default()
                }),
                result: None,
            })
        });
        broadcast_client
            .expect_broadcast_tx()
            .once()
            .returning(|_| Ok(TxResponse::default()));
        broadcast_client.expect_get_tx().once().returning(|_| {
            Ok(GetTxResponse {
                tx_response: Some(TxResponse {
                    code: 0,
                    ..TxResponse::default()
                }),
                ..GetTxResponse::default()
            })
        });

        let broadcaster =
            BroadcasterBuilder::new(broadcast_client, ECDSASigningKey::random(), Config::default()).build();
        let (client, _driver) = QueuedBroadcaster::new(broadcaster, gas_limit, tx_count, broadcast_interval);
        let tx = client.client();

        let handler = tokio::spawn(async move {
            assert!(client.run().await.is_ok());
        });

        for _ in 0..tx_count {
            tx.broadcast(dummy_msg()).await.unwrap();
        }
        sleep(broadcast_interval).await;

        handler.abort();
    }

    #[test]
    async fn should_broadcast_when_gas_limit_has_been_reached() {
        let tx_count = 10;
        let gas_limit = 100;
        let gas_used = 10;
        let mut broadcast_client = MockBroadcastClient::new();
        broadcast_client.expect_simulate().times(tx_count).returning(move |_| {
            Ok(SimulateResponse {
                gas_info: Some(GasInfo {
                    gas_used,
                    ..Default::default()
                }),
                result: None,
            })
        });
        broadcast_client.expect_simulate().times(2).returning(move |_| {
            Ok(SimulateResponse {
                gas_info: Some(GasInfo {
                    gas_used: gas_used * (tx_count as u64),
                    ..Default::default()
                }),
                result: None,
            })
        });
        broadcast_client
            .expect_broadcast_tx()
            .times(2)
            .returning(|_| Ok(TxResponse::default()));
        broadcast_client.expect_get_tx().times(2).returning(|_| {
            Ok(GetTxResponse {
                tx_response: Some(TxResponse {
                    code: 0,
                    ..TxResponse::default()
                }),
                ..GetTxResponse::default()
            })
        });

        let broadcaster =
            BroadcasterBuilder::new(broadcast_client, ECDSASigningKey::random(), Config::default()).build();
        let (client, _driver) = QueuedBroadcaster::new(broadcaster, gas_limit, tx_count, Duration::from_secs(5));

        let tx = client.client();
        for _ in 0..tx_count {
            tx.broadcast(dummy_msg()).await.unwrap();
        }
        drop(tx);

        assert!(client.run().await.is_ok());
    }

    #[test]
    async fn should_broadcast_when_forced_to() {
        let tx_count = 10;
        let gas_limit = 100;
        let gas_used = 2;
        let mut broadcast_client = MockBroadcastClient::new();
        broadcast_client.expect_simulate().times(tx_count).returning(move |_| {
            Ok(SimulateResponse {
                gas_info: Some(GasInfo {
                    gas_used,
                    ..Default::default()
                }),
                result: None,
            })
        });
        broadcast_client.expect_simulate().once().returning(move |_| {
            Ok(SimulateResponse {
                gas_info: Some(GasInfo {
                    gas_used: gas_used * (tx_count as u64),
                    ..Default::default()
                }),
                result: None,
            })
        });
        broadcast_client
            .expect_broadcast_tx()
            .once()
            .returning(|_| Ok(TxResponse::default()));
        broadcast_client.expect_get_tx().once().returning(|_| {
            Ok(GetTxResponse {
                tx_response: Some(TxResponse {
                    code: 0,
                    ..TxResponse::default()
                }),
                ..GetTxResponse::default()
            })
        });

        let broadcaster =
            BroadcasterBuilder::new(broadcast_client, ECDSASigningKey::random(), Config::default()).build();
        let (client, driver) = QueuedBroadcaster::new(broadcaster, gas_limit, tx_count, Duration::from_secs(5));

        let tx = client.client();
        for _ in 0..tx_count {
            tx.broadcast(dummy_msg()).await.unwrap();
        }
        let handler = tokio::spawn(async move {
            assert!(client.run().await.is_ok());
        });

        sleep(Duration::from_secs(1)).await;
        driver.force_broadcast().await.unwrap();
        drop(tx);

        assert!(handler.await.is_ok());
    }

    fn dummy_msg() -> Any {
        MsgSend {
            from_address: TMAddress::new("", &[1, 2, 3]).unwrap(),
            to_address: TMAddress::new("", &[4, 5, 6]).unwrap(),
            amount: vec![],
        }
        .to_any()
        .unwrap()
    }
}
