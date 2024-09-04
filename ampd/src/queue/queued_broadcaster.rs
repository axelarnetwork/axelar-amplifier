use async_trait::async_trait;
use cosmrs::tx::MessageExt;
use cosmrs::{Any, Gas};
use error_stack::{self, Report, ResultExt};
use mockall::automock;
use thiserror::Error;
use tokio::select;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Interval;
use tracing::{debug, info, warn};

use super::msg_queue::MsgQueue;
use super::proto;
use crate::broadcaster::confirm_tx::{TxResponse, TxStatus};
use crate::broadcaster::Broadcaster;

type Result<T = ()> = error_stack::Result<T, Error>;
type MsgAndResponseCallback = (Any, oneshot::Sender<Result>);

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
    #[error("failed to confirm transaction")]
    TxConfirmation,
    #[error("failed to decode tx response")]
    DecodeTxResponse(#[from] prost::DecodeError),
    #[error("no clients for tx broadcasts connected")]
    NoClients,
}

#[automock]
#[async_trait]
pub trait BroadcasterClient {
    async fn broadcast(&self, tx: Any) -> Result;
}

pub struct QueuedBroadcasterClient {
    sender: mpsc::Sender<MsgAndResponseCallback>,
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
    channel: Option<(
        mpsc::Sender<MsgAndResponseCallback>,
        mpsc::Receiver<MsgAndResponseCallback>,
    )>,
    channel_capacity: usize,
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
            channel: None,
            broadcast_interval,
            channel_capacity: capacity,
        }
    }

    pub async fn run(
        mut self,
        tx_hash_sender: mpsc::Sender<String>,
        mut tx_response_receiver: mpsc::Receiver<TxResponse>,
    ) -> Result {
        // drop the internal sender, so broadcast stops as soon as there are no external clients connected anymore
        let (_, mut rx) = self.channel.take().ok_or(Error::NoClients)?;

        loop {
            select! {
                msg = rx.recv() => match msg {
                    Some(msg_and_response_callback) => self.handle_msg(msg_and_response_callback, &tx_hash_sender).await?,
                    // no more senders, so stop broadcasting
                    None => break,
                },
                // when traffic is low, periodically broadcast all queued messages so latency doesn't get too high
                _ = self.broadcast_interval.tick() => {
                    self.broadcast_all(&tx_hash_sender).await?;
                    self.broadcast_interval.reset();
                },
                Some(tx_res) = tx_response_receiver.recv() => handle_tx_response(tx_res).await?,
            }
        }

        self.clean_up(tx_hash_sender, tx_response_receiver).await
    }

    pub fn client(&mut self) -> QueuedBroadcasterClient {
        let (sender, _) = self
            .channel
            .get_or_insert(mpsc::channel(self.channel_capacity));
        QueuedBroadcasterClient {
            sender: sender.clone(),
        }
    }

    async fn broadcast_all(&mut self, tx_hash_sender: &mpsc::Sender<String>) -> Result {
        let msgs = self.queue.pop_all();

        match msgs.len() {
            0 => Ok(()),
            n => {
                info!(message_count = n, "ready to broadcast messages");

                let batch_req = proto::axelar::auxiliary::v1beta1::BatchRequest {
                    sender: self.broadcaster.sender_address().as_ref().to_bytes(),
                    messages: msgs,
                }
                .to_any()
                .expect("failed to serialize proto message for batch request");

                let tx_hash = self
                    .broadcaster
                    .broadcast(vec![batch_req])
                    .await
                    .change_context(Error::Broadcast)?
                    .txhash;
                tx_hash_sender
                    .send(tx_hash)
                    .await
                    .change_context(Error::TxConfirmation)?;

                Ok(())
            }
        }
    }

    async fn handle_msg(
        &mut self,
        (msg, callback): MsgAndResponseCallback,
        tx_hash_sender: &mpsc::Sender<String>,
    ) -> Result<()> {
        match self.broadcaster.estimate_fee(vec![msg.clone()]).await {
            Ok(fee) => {
                callback
                    .send(Ok(()))
                    .map_err(|_| Report::new(Error::Client))?;

                if fee.gas_limit.saturating_add(self.queue.gas_cost()) >= self.batch_gas_limit {
                    warn!(
                        queue_size = self.queue.len(),
                        queue_gas_cost = self.queue.gas_cost(),
                        "exceeded batch gas limit. gas limit can be adjusted in ampd config"
                    );
                    self.broadcast_all(tx_hash_sender).await?;
                    self.broadcast_interval.reset();
                }

                self.queue
                    .push(msg, fee.gas_limit)
                    .change_context(Error::Queue)?;
            }
            Err(err) => {
                callback
                    .send(Err(err).change_context(Error::EstimateFee))
                    .map_err(|_| Report::new(Error::Client))?;
            }
        }

        Ok(())
    }

    async fn clean_up(
        mut self,
        tx_hash_sender: mpsc::Sender<String>,
        mut response_receiver: mpsc::Receiver<TxResponse>,
    ) -> Result {
        info!("exiting broadcaster");

        self.broadcast_all(&tx_hash_sender).await?;
        // drop the tx hash sender so the receiver of that channel knows there won't be any more messages
        drop(tx_hash_sender);
        while let Some(tx_res) = response_receiver.recv().await {
            handle_tx_response(tx_res).await?;
        }

        Ok(())
    }
}

async fn handle_tx_response(tx_res: TxResponse) -> Result {
    let tx_hash = tx_res.response.txhash;

    match tx_res.status {
        TxStatus::Success => {
            tx_res.response.logs.iter().for_each(|log| {
                let msg_index = log.msg_index;

                log.events
                    .iter()
                    .enumerate()
                    .for_each(|(event_index, event)| {
                        debug!(tx_hash, msg_index, event_index, "tx event {:?}", event);
                    });
            });
        }
        TxStatus::Failure => {
            warn!(
                tx_hash,
                log = tx_res.response.raw_log,
                error_code = tx_res.response.code,
                "tx failed"
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use cosmrs::bank::MsgSend;
    use cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse;
    use cosmrs::tx::{Fee, MessageExt, Msg};
    use cosmrs::{AccountId, Any};
    use error_stack::Report;
    use futures::StreamExt;
    use tokio::sync::mpsc;
    use tokio::test;
    use tokio::time::{interval, timeout, Duration, Instant};
    use tokio_stream::wrappers::ReceiverStream;

    use super::{Error, QueuedBroadcaster};
    use crate::broadcaster::{self, MockBroadcaster};
    use crate::queue::proto;
    use crate::queue::queued_broadcaster::BroadcasterClient;
    use crate::PREFIX;

    #[test]
    async fn should_ignore_msg_when_fee_estimation_fails() {
        let mut broadcaster = MockBroadcaster::new();
        broadcaster
            .expect_estimate_fee()
            .return_once(|_| Err(Report::new(broadcaster::Error::FeeEstimation)));

        let (tx_confirmer_sender, _tx_confirmer_receiver) = mpsc::channel(1000);
        let (tx_res_sender, tx_res_receiver) = mpsc::channel(1000);
        let broadcast_interval = interval(Duration::from_secs(5));
        let mut queued_broadcaster =
            QueuedBroadcaster::new(broadcaster, 100, 10, broadcast_interval);
        let client = queued_broadcaster.client();
        let handle = tokio::spawn(queued_broadcaster.run(tx_confirmer_sender, tx_res_receiver));

        assert!(matches!(
            client
                .broadcast(dummy_msg())
                .await
                .unwrap_err()
                .current_context(),
            Error::EstimateFee
        ));
        drop(client);
        drop(tx_res_sender);

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
            .expect_sender_address()
            .once()
            .returning(|| AccountId::new(PREFIX, &[1, 2, 3]).unwrap().into());
        broadcaster
            .expect_broadcast()
            .once()
            .returning(move |msgs| {
                assert_eq!(msgs.len(), 1);
                let msg = msgs.first().unwrap();
                let msg = proto::axelar::auxiliary::v1beta1::BatchRequest::from_any(msg).unwrap();
                assert_eq!(msg.messages.len(), tx_count);

                tx.try_send(())
                    .expect("Failed to send broadcast completion signal");

                Ok(TxResponse::default())
            });

        let (tx_confirmer_sender, tx_confirmer_receiver) = mpsc::channel(1000);
        let (tx_res_sender, tx_res_receiver) = mpsc::channel(1000);
        let mut broadcast_interval = interval(interval_duration);
        broadcast_interval.tick().await;
        let mut queued_broadcaster =
            QueuedBroadcaster::new(broadcaster, batch_gas_limit, tx_count, broadcast_interval);
        let client = queued_broadcaster.client();
        let handle = tokio::spawn(queued_broadcaster.run(tx_confirmer_sender, tx_res_receiver));

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
            Err(_) => panic!("broadcast did not occur within the expected timeframe"),
        }

        drop(client);
        drop(tx_res_sender);

        assert!(handle.await.unwrap().is_ok());
        assert_eq!(ReceiverStream::new(tx_confirmer_receiver).count().await, 1);
    }

    #[test(start_paused = true)]
    async fn should_broadcast_full_batches_in_high_load() {
        let tx_count = 20;
        let batch_size = 10;
        let batch_gas_limit = 100;
        let gas_limit = 11; // This will cause a batch to be full after 9 messages
        let interval_duration = Duration::from_secs(5);

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
            .expect_sender_address()
            .times(3)
            .returning(|| AccountId::new(PREFIX, &[1, 2, 3]).unwrap().into());
        let mut call_count = 0;
        broadcaster
            .expect_broadcast()
            .times(3)
            .returning(move |msgs| {
                call_count += 1;

                assert_eq!(msgs.len(), 1);
                let msg = msgs.first().unwrap();
                let msg = proto::axelar::auxiliary::v1beta1::BatchRequest::from_any(msg).unwrap();

                if call_count < 3 {
                    assert_eq!(msg.messages.len(), 9);
                } else {
                    assert_eq!(msg.messages.len(), 2);
                }

                Ok(TxResponse::default())
            });
        let (tx_confirmer_sender, tx_confirmer_receiver) = mpsc::channel(1000);
        let (tx_res_sender, tx_res_receiver) = mpsc::channel(1000);
        let mut broadcast_interval = interval(interval_duration);
        // get rid of tick on startup
        broadcast_interval.tick().await;
        let mut queued_broadcaster =
            QueuedBroadcaster::new(broadcaster, batch_gas_limit, batch_size, broadcast_interval);
        let client = queued_broadcaster.client();
        let handle = tokio::spawn(queued_broadcaster.run(tx_confirmer_sender, tx_res_receiver));

        let start_time = Instant::now();

        for _ in 0..tx_count {
            client.broadcast(dummy_msg()).await.unwrap();
        }
        // Advance time by a small amount to allow processing
        tokio::time::advance(Duration::from_millis(100)).await;

        let elapsed = start_time.elapsed();
        // Assert that broadcasts happened faster than the interval
        assert!(elapsed < interval_duration);

        drop(client);
        drop(tx_res_sender);

        assert_eq!(ReceiverStream::new(tx_confirmer_receiver).count().await, 3);
        assert!(handle.await.unwrap().is_ok());
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
            .expect_sender_address()
            .times(2)
            .returning(|| AccountId::new(PREFIX, &[1, 2, 3]).unwrap().into());
        let mut broadcast_count = 0;
        broadcaster
            .expect_broadcast()
            .times(2)
            .returning(move |msgs| {
                broadcast_count += 1;

                assert_eq!(msgs.len(), 1);
                let msg = msgs.first().unwrap();
                let msg = proto::axelar::auxiliary::v1beta1::BatchRequest::from_any(msg).unwrap();

                if broadcast_count == 1 {
                    assert_eq!(msg.messages.len(), tx_count - 1);
                } else {
                    assert_eq!(msg.messages.len(), 1);
                }

                Ok(TxResponse::default())
            });

        let (tx_confirmer_sender, tx_confirmer_receiver) = mpsc::channel(1000);
        let (tx_res_sender, tx_res_receiver) = mpsc::channel(1000);
        let mut broadcast_interval = interval(Duration::from_secs(5));
        // get rid of tick on startup
        broadcast_interval.tick().await;
        let mut queued_broadcaster =
            QueuedBroadcaster::new(broadcaster, batch_gas_limit, tx_count, broadcast_interval);
        let client = queued_broadcaster.client();
        let handle = tokio::spawn(queued_broadcaster.run(tx_confirmer_sender, tx_res_receiver));

        for _ in 0..tx_count {
            client.broadcast(dummy_msg()).await.unwrap();
        }
        drop(client);
        drop(tx_res_sender);
        assert_eq!(ReceiverStream::new(tx_confirmer_receiver).count().await, 2);

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
