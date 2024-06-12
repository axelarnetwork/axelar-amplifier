use std::time::Duration;

use async_trait::async_trait;
use cosmrs::{Any, Gas};
use error_stack::{self, Report, ResultExt};
use mockall::automock;
use thiserror::Error;
use tokio::sync::oneshot;
use tokio::time;
use tokio::{select, sync::mpsc};
use tracing::info;
use tracing::warn;

use super::msg_queue::MsgQueue;
use crate::broadcaster::Broadcaster;

type Result<T = ()> = error_stack::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed estimating fee for message")]
    EstimateFee,
    #[error("failed broadcasting messages in queue")]
    Broadcast,
    #[error("failed to queue message")]
    Queue,
}

#[automock]
#[async_trait]
pub trait BroadcasterClient {
    async fn broadcast(&self, tx: Any) -> Result;
}

pub struct QueuedBroadcasterClient {
    sender: mpsc::Sender<(Any, oneshot::Sender<Result>)>,
}

#[async_trait]
impl BroadcasterClient for QueuedBroadcasterClient {
    async fn broadcast(&self, msg: Any) -> Result {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send((msg, tx))
            .await
            .map_err(|_| Report::new(Error::Broadcast))?;

        rx.await.expect("sender dropped")
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
    channel: (
        mpsc::Sender<(Any, oneshot::Sender<Result>)>,
        mpsc::Receiver<(Any, oneshot::Sender<Result>)>,
    ),
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
    ) -> Self {
        Self {
            broadcaster,
            queue: MsgQueue::default(),
            batch_gas_limit,
            broadcast_interval,
            channel: mpsc::channel(capacity),
        }
    }

    pub async fn run(self) -> Result {
        let (tx, mut rx) = self.channel;
        drop(tx);

        let mut queue = self.queue;
        let mut broadcaster = self.broadcaster;

        let mut interval = time::interval(self.broadcast_interval);

        loop {
            select! {
                msg = rx.recv() => match msg {
                    None => break,
                    Some((msg, tx)) => {
                        let fee = match broadcaster.estimate_fee(vec![msg.clone()]).await {
                            Ok(fee) => {
                                tx.send(Ok(())).expect("receiver dropped");
                                fee
                            },
                            Err(err) => {
                                tx.send(Err(err).change_context(Error::EstimateFee)).expect("receiver dropped");
                                continue;
                            }
                        };

                        if fee.gas_limit.saturating_add(queue.gas_cost()) >= self.batch_gas_limit {
                            warn!(queue_size = queue.len(), queue_gas_cost = queue.gas_cost(), "exceeded batch gas limit. gas limit can be adjusted in ampd config");
                            broadcast_all(&mut queue, &mut broadcaster).await?;
                            interval.reset();
                        }

                        let message_type = msg.type_url.clone();
                        queue.push(msg, fee.gas_limit).change_context(Error::Queue)?;
                        info!(
                            message_type,
                            queue_size = queue.len(),
                            queue_gas_cost = queue.gas_cost(),
                            "pushed a new message into the queue"
                        );
                    }
                },
                _ = interval.tick() => {
                    broadcast_all(&mut queue, &mut broadcaster).await?;
                    interval.reset();
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
    use cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse;
    use cosmrs::tx::Fee;
    use cosmrs::Any;
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

        let client = QueuedBroadcaster::new(
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
        let broadcast_interval = Duration::from_millis(100);
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

        let client =
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

        let client = QueuedBroadcaster::new(
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

    fn dummy_msg() -> Any {
        MsgSend {
            from_address: AccountId::new("", &[1, 2, 3]).unwrap(),
            to_address: AccountId::new("", &[4, 5, 6]).unwrap(),
            amount: vec![],
        }
        .to_any()
        .unwrap()
    }
}
