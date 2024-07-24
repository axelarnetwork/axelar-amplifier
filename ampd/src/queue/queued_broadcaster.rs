use async_trait::async_trait;
use cosmrs::{Any, Gas};
use error_stack::{self, Report, ResultExt};
use mockall::automock;
use thiserror::Error;
use tokio::select;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Interval;
use tracing::{info, warn};

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
    channel: Option<(mpsc::Sender<MsgAndResChan>, mpsc::Receiver<MsgAndResChan>)>,
    broadcast_interval: Interval,
}

impl<T> QueuedBroadcaster<T>
where
    T: Broadcaster,
{
    pub fn new(
        broadcaster: T,
        batch_gas_limit: Gas,
        capacity: usize,
        broadcast_interval: Interval,
    ) -> Self {
        Self {
            broadcaster,
            queue: MsgQueue::default(),
            batch_gas_limit,
            channel: Some(mpsc::channel(capacity)),
            broadcast_interval,
        }
    }

    pub async fn run(mut self) -> Result {
        let (_, mut rx) = self
            .channel
            .take()
            .expect("broadcast channel is expected to be set during initialization and must be available when running the broadcaster");

        loop {
            select! {
                msg = rx.recv() => match msg {
                    None => break,
                    Some(msg_and_res_chan) => self.handle_msg(msg_and_res_chan).await?,
                },
                _ = self.broadcast_interval.tick() => {
                    self.broadcast_all().await?;
                    self.broadcast_interval.reset();
                },
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

    async fn handle_msg(&mut self, msg_and_res_chan: MsgAndResChan) -> Result<()> {
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
                    self.broadcast_interval.reset();
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

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use cosmrs::bank::MsgSend;
    use cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse;
    use cosmrs::tx::{Fee, Msg};
    use cosmrs::{AccountId, Any};
    use error_stack::Report;
    use tokio::sync::mpsc;
    use tokio::test;
    use tokio::time::{interval, timeout, Duration, Instant};

    use super::{Error, QueuedBroadcaster};
    use crate::broadcaster::{self, MockBroadcaster};
    use crate::queue::queued_broadcaster::BroadcasterClient;

    #[test]
    async fn should_ignore_msg_when_fee_estimation_fails() {
        let mut broadcaster = MockBroadcaster::new();
        broadcaster
            .expect_estimate_fee()
            .return_once(|_| Err(Report::new(broadcaster::Error::FeeEstimation)));

        let broadcast_interval = interval(Duration::from_secs(5));
        let queued_broadcaster = QueuedBroadcaster::new(broadcaster, 100, 10, broadcast_interval);
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

    #[test(start_paused = true)]
    async fn should_broadcast_after_interval_in_low_load() {
        let tx_count = 5; // Less than what would exceed batch_gas_limit
        let batch_gas_limit = 100;
        let gas_limit = 10;
        let interval_duration = Duration::from_secs(5);

        let (tx, mut rx) = mpsc::channel(5);

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
            .times(1)
            .returning(move |msgs| {
                assert_eq!(msgs.len(), tx_count);
                tx.try_send(())
                    .expect("Failed to send broadcast completion signal");
                Ok(TxResponse::default())
            });

        let mut broadcast_interval = interval(interval_duration);
        broadcast_interval.tick().await;

        let queued_broadcaster =
            QueuedBroadcaster::new(broadcaster, batch_gas_limit, tx_count, broadcast_interval);
        let client = queued_broadcaster.client();
        let _handle = tokio::spawn(queued_broadcaster.run());

        let start_time = Instant::now();

        for _ in 0..tx_count {
            client.broadcast(dummy_msg()).await.unwrap();
        }

        // Advance time to just after one interval
        tokio::time::advance(interval_duration + Duration::from_millis(10)).await;

        match timeout(interval_duration, rx.recv()).await {
            Ok(_) => {
                let elapsed = start_time.elapsed();
                assert!(elapsed > interval_duration);
                assert!(elapsed < interval_duration * 2);
            }
            Err(_) => panic!("Broadcast did not occur within the expected timeframe"),
        }
    }

    #[test(start_paused = true)]
    async fn should_broadcast_full_batches_in_high_load() {
        let tx_count = 20;
        let batch_size = 10;
        let batch_gas_limit = 100;
        let gas_limit = 11; // This will cause a batch to be full after 9 messages
        let interval_duration = Duration::from_secs(5);

        let mut broadcaster = MockBroadcaster::new();
        broadcaster.expect_estimate_fee().returning(move |_| {
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
                assert_eq!(msgs.len(), 9);

                Ok(TxResponse::default())
            });
        broadcaster
            .expect_broadcast()
            .once()
            .returning(move |msgs| {
                assert_eq!(msgs.len(), 9);

                Ok(TxResponse::default())
            });

        let mut broadcast_interval = interval(interval_duration);
        broadcast_interval.tick().await;

        let queued_broadcaster =
            QueuedBroadcaster::new(broadcaster, batch_gas_limit, batch_size, broadcast_interval);
        let client = queued_broadcaster.client();
        let _handle = tokio::spawn(queued_broadcaster.run());

        let start_time = Instant::now();

        for _ in 0..tx_count {
            client.broadcast(dummy_msg()).await.unwrap();
        }

        // Advance time by a small amount to allow processing
        tokio::time::advance(Duration::from_millis(100)).await;

        let elapsed = start_time.elapsed();

        // Assert that broadcasts happened faster than the interval
        assert!(elapsed < interval_duration);
    }

    #[test(start_paused = true)]
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
                assert_eq!(msgs.len(), tx_count - 1);

                Ok(TxResponse::default())
            });
        broadcaster
            .expect_broadcast()
            .once()
            .returning(move |msgs| {
                assert_eq!(msgs.len(), 1);
                Ok(TxResponse::default())
            });

        let mut broadcast_interval = interval(Duration::from_secs(5));
        // get rid of tick on startup
        broadcast_interval.tick().await;

        let queued_broadcaster =
            QueuedBroadcaster::new(broadcaster, batch_gas_limit, tx_count, broadcast_interval);
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
