use std::time::Duration;

use async_trait::async_trait;
use cosmrs::{tx::Msg, Any, Gas};
use error_stack::{self, Report, ResultExt};
use mockall::automock;
use thiserror::Error;
use tokio::time;
use tokio::{select, sync::mpsc};
use tracing::info;

use super::msg_queue::MsgQueue;
use crate::broadcaster::Broadcaster;

type Result<T = ()> = error_stack::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed estimating fee for message")]
    EstimateFee,
    #[error("failed broadcasting messages in queue")]
    Broadcast,
    #[error("failed encoding message to Protobuf Any {0}")]
    Proto(String),
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

#[automock]
#[async_trait]
pub trait BroadcasterClient {
    async fn broadcast<T>(&self, tx: T) -> Result
    where
        T: Msg + Send + Sync + 'static;
}

pub struct QueuedBroadcasterClient {
    sender: mpsc::Sender<Any>,
}

#[async_trait]
impl BroadcasterClient for QueuedBroadcasterClient {
    async fn broadcast<T>(&self, tx: T) -> Result
    where
        T: Msg + Send + Sync + 'static,
    {
        self.sender
            .send(
                tx.into_any()
                    .map_err(|err| Report::new(Error::Proto(err.to_string())))?,
            )
            .await
            .map_err(|_| Report::new(Error::Broadcast))
    }
}

pub struct QueuedBroadcaster<T>
where
    T: Broadcaster,
{
    broadcaster: T,
    queue: MsgQueue,
    batch_gas_limit: Gas,
    broadcast_interval: Duration,
    channel: (mpsc::Sender<Any>, mpsc::Receiver<Any>),
    broadcast_rx: mpsc::Receiver<()>,
}

impl<T> QueuedBroadcaster<T>
where
    T: Broadcaster,
{
    pub fn new(
        broadcaster: T,
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
                  let fee = broadcaster.estimate_fee(vec![msg.clone()]).await.change_context(Error::EstimateFee)?;

                  if fee.gas_limit + queue.gas_cost() >= self.batch_gas_limit {
                    interval.reset();
                    broadcast_all(&mut queue, &mut broadcaster).await?;
                  }

                  let message_type = msg.type_url.clone();
                  queue.push(msg, fee.gas_limit);
                  info!(
                    message_type,
                    queue_size = queue.len(),
                    queue_gas_cost = queue.gas_cost(),
                    "pushed a new message into the queue"
                  );
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

async fn broadcast_all<T>(queue: &mut MsgQueue, broadcaster: &mut T) -> Result
where
    T: Broadcaster,
{
    let msgs = queue.pop_all();

    match msgs.len() {
        0 => Ok(()),
        n => {
            info!(message_count = n, "ready to broadcast messages");

            broadcaster
                .broadcast(msgs)
                .await
                .map(|_| ())
                .change_context(Error::Broadcast)
        }
    }
}

#[cfg(test)]
mod test {
    use cosmos_sdk_proto::cosmos::base::abci::v1beta1::TxResponse;
    use cosmrs::tx::Fee;
    use cosmrs::{bank::MsgSend, tx::Msg, AccountId};
    use tokio::test;
    use tokio::time::{sleep, Duration};

    use super::QueuedBroadcaster;
    use crate::broadcaster::MockBroadcaster;
    use crate::queue::queued_broadcaster::BroadcasterClient;

    #[test]
    async fn should_not_broadcast_when_gas_limit_has_not_been_reached() {
        let tx_count = 9;
        let batch_gas_limit = 100;
        let gas_limit = 10;

        let mut broadcaster = MockBroadcaster::new();
        broadcaster
            .expect_estimate_fee()
            .times(tx_count)
            .returning(move |_| {
                Ok(Fee {
                    gas_limit,
                    amount: vec![],
                    granter: None,
                    payer: None,
                })
            });
        broadcaster
            .expect_broadcast()
            .once()
            .returning(move |msgs| {
                assert!(msgs.len() == tx_count);

                Ok(TxResponse::default())
            });

        let (client, _driver) = QueuedBroadcaster::new(
            broadcaster,
            batch_gas_limit,
            tx_count,
            Duration::from_secs(5),
        );

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
        let batch_gas_limit = 100;
        let broadcast_interval = Duration::from_secs(1);
        let gas_limit = 10;

        let mut broadcaster = MockBroadcaster::new();
        broadcaster
            .expect_estimate_fee()
            .times(tx_count)
            .returning(move |_| {
                Ok(Fee {
                    gas_limit,
                    amount: vec![],
                    granter: None,
                    payer: None,
                })
            });
        broadcaster
            .expect_broadcast()
            .once()
            .returning(move |msgs| {
                assert!(msgs.len() == tx_count);

                Ok(TxResponse::default())
            });

        let (client, _driver) =
            QueuedBroadcaster::new(broadcaster, batch_gas_limit, tx_count, broadcast_interval);
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
        let batch_gas_limit = 100;
        let gas_limit = 11;

        let mut broadcaster = MockBroadcaster::new();
        broadcaster
            .expect_estimate_fee()
            .times(tx_count)
            .returning(move |_| {
                Ok(Fee {
                    gas_limit,
                    amount: vec![],
                    granter: None,
                    payer: None,
                })
            });
        broadcaster
            .expect_broadcast()
            .once()
            .returning(move |msgs| {
                assert!(msgs.len() == tx_count - 1);

                Ok(TxResponse::default())
            });
        broadcaster
            .expect_broadcast()
            .once()
            .returning(move |msgs| {
                assert!(msgs.len() == 1);

                Ok(TxResponse::default())
            });

        let (client, _driver) = QueuedBroadcaster::new(
            broadcaster,
            batch_gas_limit,
            tx_count,
            Duration::from_secs(5),
        );

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
        let batch_gas_limit = 100;
        let gas_limit = 2;

        let mut broadcaster = MockBroadcaster::new();
        broadcaster
            .expect_estimate_fee()
            .times(tx_count)
            .returning(move |_| {
                Ok(Fee {
                    gas_limit,
                    amount: vec![],
                    granter: None,
                    payer: None,
                })
            });
        broadcaster
            .expect_broadcast()
            .once()
            .returning(move |msgs| {
                assert!(msgs.len() == tx_count);

                Ok(TxResponse::default())
            });

        let (client, driver) = QueuedBroadcaster::new(
            broadcaster,
            batch_gas_limit,
            tx_count,
            Duration::from_secs(5),
        );

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

    fn dummy_msg() -> impl Msg {
        MsgSend {
            from_address: AccountId::new("", &[1, 2, 3]).unwrap(),
            to_address: AccountId::new("", &[4, 5, 6]).unwrap(),
            amount: vec![],
        }
    }
}
