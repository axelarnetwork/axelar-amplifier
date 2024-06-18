use std::time::Duration;

use async_trait::async_trait;
use axelar_wasm_std::FnExt;
use cosmrs::{Any, Gas};
use error_stack::{self, Report, ResultExt};
use mockall::automock;
use thiserror::Error;
use tokio::select;
use tokio::sync::{mpsc, oneshot};
use tokio::time;
use tracing::info;
use tracing::warn;

use super::msg_queue::MsgQueue;
use crate::broadcaster::Broadcaster;

type Result<T = ()> = error_stack::Result<T, Error>;
type MsgAndResChan = (Any, oneshot::Sender<Result>);

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed estimating fee for message")]
    EstimateFee,
    #[error("failed broadcasting messages in queue")]
    Broadcast,
    #[error("failed returning response to client")]
    Client,
    #[error("failed to queue message")]
    Queue,
}

#[automock]
#[async_trait]
pub trait BroadcasterClient {
    async fn broadcast(&self, tx: Any) -> Result;
}

pub struct QueuedBroadcasterClient {
    sender: mpsc::Sender<MsgAndResChan>,
}

#[async_trait]
impl BroadcasterClient for QueuedBroadcasterClient {
    async fn broadcast(&self, msg: Any) -> Result {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send((msg, tx))
            .await
            .change_context(Error::Broadcast)?;

        rx.await.change_context(Error::Broadcast)?
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
    channel: Option<(mpsc::Sender<MsgAndResChan>, mpsc::Receiver<MsgAndResChan>)>,
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
            channel: Some(mpsc::channel(capacity)),
        }
    }

    pub async fn run(mut self) -> Result {
        let (_, mut rx) = self
            .channel
            .take()
            .expect("broadcast channel is expected to be set during initialization and must be available when running the broadcaster");
        let mut interval = time::interval(self.broadcast_interval);

        loop {
            select! {
                msg = rx.recv() => match msg {
                    None => break,
                    Some(msg_and_res_chan) => interval = self.handle_msg(interval, msg_and_res_chan).await?,
                },
                _ = interval.tick() => self.broadcast_all().await?.then(|_| {interval.reset()}),
            }
        }

        self.broadcast_all().await?;

        Ok(())
    }

    pub fn client(&self) -> QueuedBroadcasterClient {
        QueuedBroadcasterClient {
            sender: self
                .channel
                .as_ref()
                .expect("broadcast channel is expected to be set during initialization and must be available when running the broadcaster")
                .0
                .clone(),
        }
    }

    async fn broadcast_all(&mut self) -> Result {
        let msgs = self.queue.pop_all();

        match msgs.len() {
            0 => Ok(()),
            n => {
                info!(message_count = n, "ready to broadcast messages");

                self.broadcaster
                    .broadcast(msgs)
                    .await
                    .map(|_| ())
                    .change_context(Error::Broadcast)
            }
        }
    }

    async fn handle_msg(
        &mut self,
        mut interval: time::Interval,
        msg_and_res_chan: MsgAndResChan,
    ) -> Result<time::Interval> {
        let (msg, tx) = msg_and_res_chan;

        match self.broadcaster.estimate_fee(vec![msg.clone()]).await {
            Ok(fee) => {
                tx.send(Ok(())).map_err(|_| Report::new(Error::Client))?;

                if fee.gas_limit.saturating_add(self.queue.gas_cost()) >= self.batch_gas_limit {
                    warn!(
                        queue_size = self.queue.len(),
                        queue_gas_cost = self.queue.gas_cost(),
                        "exceeded batch gas limit. gas limit can be adjusted in ampd config"
                    );
                    self.broadcast_all().await?;
                    interval.reset();
                }

                let message_type = msg.type_url.clone();
                self.queue
                    .push(msg, fee.gas_limit)
                    .change_context(Error::Queue)?;
                info!(
                    message_type,
                    queue_size = self.queue.len(),
                    queue_gas_cost = self.queue.gas_cost(),
                    "pushed a new message into the queue"
                );
            }
            Err(err) => {
                tx.send(Err(err).change_context(Error::EstimateFee))
                    .map_err(|_| Report::new(Error::Client))?;
            }
        }

        Ok(interval)
    }
}

#[cfg(test)]
mod test {
    use cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse;
    use cosmrs::tx::Fee;
    use cosmrs::Any;
    use cosmrs::{bank::MsgSend, tx::Msg, AccountId};
    use error_stack::Report;
    use tokio::test;
    use tokio::time::{sleep, Duration};

    use super::{Error, QueuedBroadcaster};
    use crate::broadcaster::{self, MockBroadcaster};
    use crate::queue::queued_broadcaster::BroadcasterClient;

    #[test]
    async fn should_ignore_msg_when_fee_estimation_fails() {
        let mut broadcaster = MockBroadcaster::new();
        broadcaster
            .expect_estimate_fee()
            .return_once(|_| Err(Report::new(broadcaster::Error::FeeEstimation)));

        let queued_broadcaster =
            QueuedBroadcaster::new(broadcaster, 100, 10, Duration::from_secs(5));
        let client = queued_broadcaster.client();
        let handle = tokio::spawn(queued_broadcaster.run());

        assert!(matches!(
            client
                .broadcast(dummy_msg())
                .await
                .unwrap_err()
                .current_context(),
            Error::EstimateFee
        ));
        drop(client);

        assert!(handle.await.unwrap().is_ok());
    }

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

        let queued_broadcaster = QueuedBroadcaster::new(
            broadcaster,
            batch_gas_limit,
            tx_count,
            Duration::from_secs(5),
        );
        let client = queued_broadcaster.client();
        let handle = tokio::spawn(queued_broadcaster.run());

        for _ in 0..tx_count {
            client.broadcast(dummy_msg()).await.unwrap();
        }
        drop(client);

        assert!(handle.await.unwrap().is_ok());
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

        let queued_broadcaster =
            QueuedBroadcaster::new(broadcaster, batch_gas_limit, tx_count, broadcast_interval);
        let client = queued_broadcaster.client();
        let handle = tokio::spawn(queued_broadcaster.run());

        for _ in 0..tx_count {
            client.broadcast(dummy_msg()).await.unwrap();
        }
        sleep(broadcast_interval).await;
        drop(client);

        assert!(handle.await.unwrap().is_ok());
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

        let queued_broadcaster = QueuedBroadcaster::new(
            broadcaster,
            batch_gas_limit,
            tx_count,
            Duration::from_secs(5),
        );
        let client = queued_broadcaster.client();
        let handle = tokio::spawn(queued_broadcaster.run());

        for _ in 0..tx_count {
            client.broadcast(dummy_msg()).await.unwrap();
        }
        drop(client);

        assert!(handle.await.unwrap().is_ok());
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
