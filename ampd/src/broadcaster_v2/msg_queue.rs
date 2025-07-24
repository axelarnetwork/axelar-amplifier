use core::pin::Pin;
use core::task::{Context, Poll};
use std::fmt::Debug;
use std::future::Future;
use std::sync::Arc;

use axelar_wasm_std::nonempty;
use cosmrs::{Any, Gas};
use error_stack::{report, Report, ResultExt};
use futures::{FutureExt, Stream};
use pin_project_lite::pin_project;
use report::{ErrorExt, LoggableError};
use tokio::sync::{mpsc, oneshot};
use tokio::time;
use tokio_stream::adapters::Fuse;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tracing::{instrument, warn};
use valuable::Valuable;

use super::{broadcaster, Error, Result};
use crate::cosmos;
use crate::types::TMAddress;

type TxResult = std::result::Result<(String, u64), Arc<Report<Error>>>;

/// Represents a message in the queue ready for broadcasting
///
/// This struct contains a Cosmos message, its estimated gas cost,
/// and a callback channel for receiving the transaction result.
#[derive(Debug)]
pub struct QueueMsg {
    pub msg: Any,
    pub gas: Gas,
    pub tx_res_callback: oneshot::Sender<TxResult>,
}

/// Client interface for submitting messages to the message queue
///
/// `MsgQueueClient` provides methods to enqueue Cosmos messages
/// for efficient batched broadcasting. It handles gas estimation and
/// result callbacks through a Future-based API.
///
/// The client is designed to be cloned and shared across multiple
/// tasks, allowing concurrent message submission from different
/// parts of the application.
///
/// # Example
///
/// ```rust,ignore
/// let (msg_queue, msg_queue_client) = MsgQueue::new_msg_queue_and_client(
///     broadcaster,
///     10,     // queue capacity
///     100000, // gas cap
///     Duration::from_secs(5)
/// )?;
///
/// // Enqueue with result callback
/// let future = msg_queue_client.enqueue(msg).await?;
/// let (tx_hash, msg_index) = future.await?;
///
/// // Enqueue without caring about the result
/// msg_queue_client.enqueue_and_forget(msg).await?;
/// ```
#[derive(Clone, Debug)]
pub struct MsgQueueClient<T>
where
    T: cosmos::CosmosClient,
{
    tx: mpsc::Sender<QueueMsg>,
    broadcaster: broadcaster::Broadcaster<T>,
}

impl<T> MsgQueueClient<T>
where
    T: cosmos::CosmosClient,
{
    /// Returns the Tendermint address associated with this client
    ///
    /// This method provides access to the underlying broadcaster's address,
    /// which represents the Cosmos account that will broadcast transactions.
    /// The address is derived from the public key used to initialize the broadcaster.
    ///
    /// # Returns
    ///
    /// A reference to the `TMAddress` of the account used for broadcasting
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let address = msg_queue_client.address();
    /// println!("Broadcasting from address: {}", address);
    /// ```
    pub fn address(&self) -> &TMAddress {
        &self.broadcaster.address
    }
    /// Enqueues a message and returns a Future for tracking its result
    ///
    /// This method:
    /// 1. Estimates the gas required for the message
    /// 2. Adds the message to the queue
    /// 3. Returns a Future that resolves when the transaction completes
    ///
    /// The returned Future will resolve to:
    /// - `Ok((tx_hash, index))` on successful broadcast
    /// - `Err` with the relevant error on failure
    ///
    /// # Arguments
    ///
    /// * `msg` - The Cosmos message to enqueue
    ///
    /// # Returns
    ///
    /// A Future that resolves to the transaction result
    ///
    /// # Errors
    ///
    /// * `Error::EstimateGas` - If gas estimation fails
    /// * `Error::EnqueueMsg` - If enqueueing fails
    /// * `Error::GasExceedsGasCap` - If the message requires more gas than allowed
    /// * `Error::ReceiveTxResult` - If the result channel is closed prematurely
    #[instrument(skip(self))]
    pub async fn enqueue(&mut self, msg: Any) -> Result<impl Future<Output = TxResult> + Send> {
        let rx = self.enqueue_with_channel(msg).await?;

        Ok(rx.map(|result| match result {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(err)) => Err(err),
            Err(err) => Err(Arc::new(err.into_report())),
        }))
    }

    /// Enqueues a message without waiting for its result
    ///
    /// This is a fire-and-forget variant of `enqueue`, useful when
    /// you don't need to track the transaction result.
    ///
    /// # Arguments
    ///
    /// * `msg` - The Cosmos message to enqueue
    ///
    /// # Returns
    ///
    /// `Ok(())` if the message was successfully enqueued
    ///
    /// # Errors
    ///
    /// * `Error::EstimateGas` - If gas estimation fails
    /// * `Error::EnqueueMsg` - If enqueueing fails
    pub async fn enqueue_and_forget(&mut self, msg: Any) -> Result<()> {
        let _rx = self.enqueue_with_channel(msg).await?;

        Ok(())
    }

    /// Internal method that handles message enqueueing
    ///
    /// This method:
    /// 1. Creates a oneshot channel for the transaction result
    /// 2. Estimates the gas required for the message
    /// 3. Creates a QueueMsg with the message and callback
    /// 4. Sends the QueueMsg to the queue
    ///
    /// # Arguments
    ///
    /// * `msg` - The Cosmos message to enqueue
    ///
    /// # Returns
    ///
    /// The receiver end of the oneshot channel for the transaction result
    ///
    /// # Errors
    ///
    /// * `Error::EstimateGas` - If gas estimation fails
    /// * `Error::EnqueueMsg` - If enqueueing fails
    async fn enqueue_with_channel(&mut self, msg: Any) -> Result<oneshot::Receiver<TxResult>> {
        let (tx, rx) = oneshot::channel();
        let gas = self.broadcaster.estimate_gas(vec![msg.clone()]).await?;

        let msg = QueueMsg {
            msg,
            gas,
            tx_res_callback: tx,
        };

        self.tx
            .send(msg)
            .await
            .map_err(Report::new)
            .change_context(Error::EnqueueMsg)?;

        Ok(rx)
    }
}

pin_project! {
    /// Message queue for batching and broadcasting Cosmos transactions
    ///
    /// `MsgQueue` collects messages to be broadcast and exposes them as a Stream.
    /// The queue has two trigger mechanisms for releasing messages:
    ///
    /// 1. When accumulated gas usage reaches the configured gas cap
    /// 2. When a configured time duration elapses (timeout mechanism)
    ///
    /// This provides efficient batching while ensuring timely processing.
    /// The Stream implementation yields non-empty vectors of queued messages
    /// that are ready for broadcasting.
    #[derive(Debug)]
    pub struct MsgQueue {
        #[pin]
        stream: Fuse<ReceiverStream<QueueMsg>>,
        #[pin]
        deadline: time::Sleep,
        queue: Queue,
        duration: time::Duration,
    }
}

impl MsgQueue {
    /// Creates a new message queue and client pair
    ///
    /// This factory method sets up a complete message queue system by creating:
    /// 1. A `MsgQueue` instance that processes and batches messages
    /// 2. A `MsgQueueClient` that can be used to enqueue messages
    ///
    /// The two components communicate through a channel with bounded capacity.
    ///
    /// # Arguments
    ///
    /// * `broadcaster` - The broadcaster instance used for gas estimation and tx sending
    /// * `msg_cap` - Capacity of the internal message channel
    /// * `gas_cap` - Maximum gas allowed per transaction batch
    /// * `duration` - Maximum time to wait before releasing queued messages
    ///
    /// # Returns
    ///
    /// * A tuple containing:
    ///   - A pinned Stream that yields batches of messages ready for broadcast
    ///   - A client for enqueueing messages to the queue
    ///
    /// The returned Stream must be polled to process messages.
    pub fn new_msg_queue_and_client<T>(
        broadcaster: broadcaster::Broadcaster<T>,
        msg_cap: usize,
        gas_cap: Gas,
        duration: time::Duration,
    ) -> (Pin<Box<MsgQueue>>, MsgQueueClient<T>)
    where
        T: cosmos::CosmosClient,
    {
        let (tx, rx) = mpsc::channel(msg_cap);

        (
            Box::pin(MsgQueue {
                stream: ReceiverStream::new(rx).fuse(),
                deadline: time::sleep(duration),
                queue: Queue::new(gas_cap),
                duration,
            }),
            MsgQueueClient { broadcaster, tx },
        )
    }
}

impl Stream for MsgQueue {
    /// The MsgQueue yields batches of messages as non-empty vectors
    type Item = nonempty::Vec<QueueMsg>;

    /// Polls the message queue and yields batched messages when ready
    ///
    /// This implementation handles three cases:
    /// 1. New message received: Add to queue, possibly triggering a batch release
    /// 2. Stream closed: Drain the queue and then terminate
    /// 3. Timeout elapsed: Release all queued messages
    ///
    /// The poll logic ensures that messages are efficiently batched while
    /// maintaining a maximum delay for any queued message.
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut me = self.as_mut().project();

        loop {
            match me.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(msg)) => {
                    // reset the deadline timer when the first message is added to an empty queue
                    if me.queue.is_empty() {
                        me.deadline.set(time::sleep(*me.duration));
                    }

                    // try to add the message to the queue
                    // if the queue returns Some, it means we have a batch ready to send
                    if let Some(msgs) = me.queue.push_or(msg, handle_queue_error) {
                        return Poll::Ready(Some(msgs));
                    }
                }
                Poll::Ready(None) => {
                    // input stream is closed, drain any remaining messages and terminate
                    return Poll::Ready(me.queue.pop_all());
                }
                Poll::Pending => {
                    // if we have no messages queued, we can't produce anything yet
                    if me.queue.is_empty() {
                        return Poll::Pending;
                    }

                    // check if the deadline has elapsed
                    // if so, flush the queue regardless of how full it is
                    return me.deadline.poll(cx).map(|_| me.queue.pop_all());
                }
            }
        }
    }
}

fn handle_queue_error(msg: QueueMsg, err: Error) {
    let QueueMsg {
        tx_res_callback, ..
    } = msg;

    let report = report!(err);
    warn!(
        error = LoggableError::from(&report).as_value(),
        "message dropped"
    );

    let _ = tx_res_callback.send(Err(Arc::new(report)));
}

#[derive(Debug)]
struct Queue {
    msgs: Vec<QueueMsg>,
    gas_cost: Gas,
    gas_cap: Gas,
}

impl Queue {
    pub fn new(gas_cap: Gas) -> Self {
        Queue {
            msgs: vec![],
            gas_cost: Gas::default(),
            gas_cap,
        }
    }

    #[instrument(skip(handle_error))]
    pub fn push_or<F>(&mut self, msg: QueueMsg, handle_error: F) -> Option<nonempty::Vec<QueueMsg>>
    where
        F: FnOnce(QueueMsg, Error),
    {
        if msg.gas > self.gas_cap {
            let err = Error::GasExceedsGasCap {
                msg_type: msg.msg.type_url.clone(),
                gas: msg.gas,
                gas_cap: self.gas_cap,
            };
            handle_error(msg, err);

            return None;
        }

        match self
            .gas_cost
            .checked_add(msg.gas)
            .filter(|gas_cost| gas_cost <= &self.gas_cap)
        {
            // if gas cost > gas cap or gas cost overflows, pop all and then push
            // the new message
            None => {
                let results = self.pop_all();

                self.gas_cost = msg.gas;
                self.msgs.push(msg);

                results
            }
            // if gas cost = gas cap, pop all including the new message
            Some(gas_cost) if gas_cost == self.gas_cap => {
                let mut results = self.pop_all().map(Vec::from).unwrap_or_default();
                results.push(msg);

                Some(results.try_into().expect("must not be empty"))
            }
            // if gas cost < gas cap, only push the new message
            Some(gas_cost) => {
                self.gas_cost = gas_cost;
                self.msgs.push(msg);

                None
            }
        }
    }

    pub fn pop_all(&mut self) -> Option<nonempty::Vec<QueueMsg>> {
        self.gas_cost = 0;
        std::mem::take(&mut self.msgs).try_into().ok()
    }

    pub fn is_empty(&self) -> bool {
        self.msgs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::{assert_err_contains, err_contains};
    use cosmos_sdk_proto::cosmos::bank::v1beta1::QueryBalanceResponse;
    use cosmos_sdk_proto::cosmos::base::v1beta1::Coin;
    use cosmrs::proto::cosmos::auth::v1beta1::QueryAccountResponse;
    use cosmrs::proto::cosmos::bank::v1beta1::MsgSend;
    use cosmrs::proto::cosmos::base::abci::v1beta1::GasInfo;
    use cosmrs::proto::cosmos::tx::v1beta1::SimulateResponse;

    use super::*;
    use crate::broadcaster_v2::dec_coin::DecCoin;
    use crate::broadcaster_v2::test_utils::create_base_account;
    use crate::broadcaster_v2::Error;
    use crate::types::{random_cosmos_public_key, TMAddress};
    use crate::PREFIX;

    fn setup_client(address: &TMAddress) -> cosmos::MockCosmosClient {
        let mut cosmos_client = cosmos::MockCosmosClient::new();
        let base_account = create_base_account(address);

        cosmos_client.expect_account().return_once(move |_| {
            Ok(QueryAccountResponse {
                account: Some(Any::from_msg(&base_account).unwrap()),
            })
        });
        cosmos_client.expect_balance().return_once(move |_| {
            Ok(QueryBalanceResponse {
                balance: Some(Coin {
                    denom: "uaxl".to_string(),
                    amount: "1000000".to_string(),
                }),
            })
        });

        cosmos_client
    }

    #[tokio::test]
    async fn msg_queue_client_address_returns_broadcaster_address() {
        let pub_key = random_cosmos_public_key();
        let expected_address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";

        let cosmos_client = setup_client(&expected_address);
        let broadcaster = broadcaster::Broadcaster::builder()
            .client(cosmos_client)
            .chain_id("chain-id".parse().unwrap())
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();

        let (_msg_queue, msg_queue_client) = MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            1000u64,
            time::Duration::from_secs(1),
        );

        assert_eq!(msg_queue_client.address(), &expected_address);
    }

    #[tokio::test]
    async fn msg_queue_client_enqueue_and_forget() {
        let gas_cap = 1000u64;
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";

        let mut cosmos_client = setup_client(&TMAddress::random(PREFIX));
        cosmos_client.expect_simulate().return_once(move |_| {
            Ok(SimulateResponse {
                gas_info: Some(GasInfo {
                    gas_wanted: gas_cap,
                    gas_used: gas_cap,
                }),
                result: None,
            })
        });
        let broadcaster = broadcaster::Broadcaster::builder()
            .client(cosmos_client)
            .chain_id("chain-id".parse().unwrap())
            .pub_key(random_cosmos_public_key())
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();

        let (mut msg_queue, mut msg_queue_client) = MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            gas_cap,
            time::Duration::from_secs(1),
        );

        msg_queue_client
            .enqueue_and_forget(dummy_msg())
            .await
            .unwrap();
        let actual = msg_queue.next().await.unwrap();

        assert_eq!(actual.as_ref().len(), 1);
        assert_eq!(actual.as_ref()[0].gas, gas_cap);
        assert_eq!(
            actual.as_ref()[0].msg.type_url,
            "/cosmos.bank.v1beta1.MsgSend"
        );

        drop(msg_queue_client);
        assert!(msg_queue.next().await.is_none());
    }

    #[tokio::test]
    async fn msg_queue_client_enqueue() {
        let gas_cap = 1000u64;
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";

        let mut cosmos_client = setup_client(&TMAddress::random(PREFIX));
        cosmos_client.expect_simulate().return_once(move |_| {
            Ok(SimulateResponse {
                gas_info: Some(GasInfo {
                    gas_wanted: gas_cap,
                    gas_used: gas_cap,
                }),
                result: None,
            })
        });
        let broadcaster = broadcaster::Broadcaster::builder()
            .client(cosmos_client)
            .chain_id("chain-id".parse().unwrap())
            .pub_key(random_cosmos_public_key())
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();

        let (mut msg_queue, mut msg_queue_client) = MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            gas_cap,
            time::Duration::from_secs(1),
        );

        let rx = msg_queue_client.enqueue(dummy_msg()).await.unwrap();
        let actual = msg_queue.next().await.unwrap();

        assert_eq!(actual.as_ref().len(), 1);
        assert_eq!(actual.as_ref()[0].gas, gas_cap);
        assert_eq!(
            actual.as_ref()[0].msg.type_url,
            "/cosmos.bank.v1beta1.MsgSend"
        );

        Vec::from(actual)
            .pop()
            .unwrap()
            .tx_res_callback
            .send(Ok(("txhash".to_string(), 10)))
            .unwrap();
        assert_eq!(rx.await.unwrap(), ("txhash".to_string(), 10));
    }

    #[tokio::test]
    async fn multiple_msg_queue_clients() {
        let gas_cap = 1000;
        let gas_cost = 100;
        let msg_count_per_client = 10;
        let client_count = 10;
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";

        let mut cosmos_client = setup_client(&TMAddress::random(PREFIX));
        cosmos_client
            .expect_clone()
            .times(client_count)
            .returning(move || {
                let mut cosmos_client = cosmos::MockCosmosClient::new();
                cosmos_client
                    .expect_simulate()
                    .times(msg_count_per_client)
                    .returning(move |_| {
                        Ok(SimulateResponse {
                            gas_info: Some(GasInfo {
                                gas_wanted: gas_cost,
                                gas_used: gas_cost,
                            }),
                            result: None,
                        })
                    });

                cosmos_client
            });
        let broadcaster = broadcaster::Broadcaster::builder()
            .client(cosmos_client)
            .chain_id("chain-id".parse().unwrap())
            .pub_key(random_cosmos_public_key())
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();

        let (mut msg_queue, msg_queue_client) = MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            gas_cap,
            time::Duration::from_secs(3),
        );

        let handles: Vec<_> = (0..client_count)
            .map(|_| {
                let mut msg_queue_client_clone = msg_queue_client.clone();

                tokio::spawn(async move {
                    for _ in 0..msg_count_per_client {
                        msg_queue_client_clone
                            .enqueue_and_forget(dummy_msg())
                            .await
                            .unwrap();
                    }
                })
            })
            .collect();

        for _ in 0..((client_count * msg_count_per_client) as u64 * gas_cost) / gas_cap {
            let actual = msg_queue.next().await.unwrap();
            assert_eq!(actual.as_ref().len() as u64, gas_cap / gas_cost);
        }
        for handle in handles {
            handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn msg_queue_client_error_handling() {
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";

        let mut cosmos_client = setup_client(&TMAddress::random(PREFIX));
        cosmos_client.expect_simulate().return_once(move |_| {
            Ok(SimulateResponse {
                gas_info: None,
                result: None,
            })
        });
        let broadcaster = broadcaster::Broadcaster::builder()
            .client(cosmos_client)
            .chain_id("chain-id".parse().unwrap())
            .pub_key(random_cosmos_public_key())
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();

        let (_msg_queue, mut msg_queue_client) = MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            1000u64,
            time::Duration::from_secs(1),
        );

        assert_err_contains!(
            msg_queue_client.enqueue_and_forget(dummy_msg()).await,
            Error,
            Error::EstimateGas
        );
    }

    #[tokio::test]
    async fn msg_queue_msg_dropped() {
        let gas_cap = 100;
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";

        let mut cosmos_client = setup_client(&TMAddress::random(PREFIX));
        cosmos_client.expect_simulate().once().returning(move |_| {
            Ok(SimulateResponse {
                gas_info: Some(GasInfo {
                    gas_wanted: gas_cap,
                    gas_used: gas_cap,
                }),
                result: None,
            })
        });
        let broadcaster = broadcaster::Broadcaster::builder()
            .client(cosmos_client)
            .chain_id("chain-id".parse().unwrap())
            .pub_key(random_cosmos_public_key())
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();

        let (mut msg_queue, mut msg_queue_client) = MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            gas_cap,
            time::Duration::from_secs(1),
        );

        let rx = msg_queue_client.enqueue(dummy_msg()).await.unwrap();
        let _ = msg_queue.next().await;

        let err = rx.await.unwrap_err();
        assert!(err_contains!(
            err.as_ref(),
            Error,
            Error::ReceiveTxResult(_)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn msg_queue_stream_timeout() {
        let gas_cap = 1000u64;
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";

        let mut cosmos_client = setup_client(&TMAddress::random(PREFIX));
        cosmos_client.expect_simulate().return_once(move |_| {
            Ok(SimulateResponse {
                gas_info: Some(GasInfo {
                    gas_wanted: gas_cap / 10,
                    gas_used: gas_cap / 10,
                }),
                result: None,
            })
        });
        let broadcaster = broadcaster::Broadcaster::builder()
            .client(cosmos_client)
            .chain_id("chain-id".parse().unwrap())
            .pub_key(random_cosmos_public_key())
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();

        let timeout = time::Duration::from_secs(3);
        let (mut msg_queue, mut msg_queue_client) =
            MsgQueue::new_msg_queue_and_client(broadcaster, 10, gas_cap, timeout);

        msg_queue_client
            .enqueue_and_forget(dummy_msg())
            .await
            .unwrap();

        let start = time::Instant::now();
        let actual = msg_queue.next().await.unwrap();
        let elapsed = start.elapsed();

        assert_eq!(actual.as_ref().len(), 1);
        assert_eq!(actual.as_ref()[0].gas, gas_cap / 10);
        assert_eq!(
            actual.as_ref()[0].msg.type_url,
            "/cosmos.bank.v1beta1.MsgSend"
        );
        assert!(elapsed >= timeout);

        // explicitly keep the stream alive until the end of the test
        drop(msg_queue_client);
    }

    #[tokio::test(start_paused = true)]
    async fn msg_queue_gas_capacity() {
        let gas_cap = 1000;
        let gas_cost = 100;
        let msg_count = 11;
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";

        let mut cosmos_client = setup_client(&TMAddress::random(PREFIX));
        cosmos_client
            .expect_simulate()
            .times(msg_count)
            .returning(move |_| {
                Ok(SimulateResponse {
                    gas_info: Some(GasInfo {
                        gas_wanted: gas_cost,
                        gas_used: gas_cost,
                    }),
                    result: None,
                })
            });
        let broadcaster = broadcaster::Broadcaster::builder()
            .client(cosmos_client)
            .chain_id("chain-id".parse().unwrap())
            .pub_key(random_cosmos_public_key())
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();

        let (mut msg_queue, mut msg_queue_client) = MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            gas_cap,
            time::Duration::from_secs(3),
        );
        let handle = tokio::spawn(async move {
            let actual = msg_queue.next().await.unwrap();
            assert_eq!(actual.as_ref().len(), 10);
            for msg in actual.as_ref() {
                assert_eq!(msg.gas, gas_cost);
                assert_eq!(msg.msg.type_url, "/cosmos.bank.v1beta1.MsgSend");
            }

            let actual = msg_queue.next().await.unwrap();
            assert_eq!(actual.as_ref().len(), 1);
            assert_eq!(actual.as_ref()[0].gas, gas_cost);
            assert_eq!(
                actual.as_ref()[0].msg.type_url,
                "/cosmos.bank.v1beta1.MsgSend"
            );
        });

        for _ in 0..msg_count {
            msg_queue_client
                .enqueue_and_forget(dummy_msg())
                .await
                .unwrap();
        }
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn msg_queue_msg_with_gas_cost_above_cap() {
        let gas_cap = 100;
        let gas_cost = 101;
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";

        let mut cosmos_client = setup_client(&TMAddress::random(PREFIX));
        cosmos_client.expect_simulate().once().returning(move |_| {
            Ok(SimulateResponse {
                gas_info: Some(GasInfo {
                    gas_wanted: gas_cost,
                    gas_used: gas_cost,
                }),
                result: None,
            })
        });
        let broadcaster = broadcaster::Broadcaster::builder()
            .client(cosmos_client)
            .chain_id("chain-id".parse().unwrap())
            .pub_key(random_cosmos_public_key())
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();

        let (mut msg_queue, mut msg_queue_client) = MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            gas_cap,
            time::Duration::from_secs(1),
        );

        let rx = msg_queue_client.enqueue(dummy_msg()).await.unwrap();
        let handle = tokio::spawn(async move {
            assert!(msg_queue.next().await.is_none());
        });

        let err = rx.await.unwrap_err();
        assert!(err_contains!(
            err.as_ref(),
            Error,
            Error::GasExceedsGasCap { .. }
        ));
        drop(msg_queue_client);
        handle.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn msg_queue_gas_overflow() {
        let gas_cap = u64::MAX;
        let gas_cost = gas_cap - 1;
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";

        let mut cosmos_client = setup_client(&TMAddress::random(PREFIX));
        cosmos_client
            .expect_simulate()
            .times(2)
            .returning(move |_| {
                Ok(SimulateResponse {
                    gas_info: Some(GasInfo {
                        gas_wanted: gas_cost,
                        gas_used: gas_cost,
                    }),
                    result: None,
                })
            });
        let broadcaster = broadcaster::Broadcaster::builder()
            .client(cosmos_client)
            .chain_id("chain-id".parse().unwrap())
            .pub_key(random_cosmos_public_key())
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();

        let (mut msg_queue, mut msg_queue_client) = MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            gas_cap,
            time::Duration::from_secs(1),
        );

        msg_queue_client
            .enqueue_and_forget(dummy_msg())
            .await
            .unwrap();
        msg_queue_client
            .enqueue_and_forget(dummy_msg())
            .await
            .unwrap();
        let actual = msg_queue.next().await.unwrap();

        assert_eq!(actual.as_ref().len(), 1);
        assert_eq!(actual.as_ref()[0].gas, gas_cost);
        assert_eq!(
            actual.as_ref()[0].msg.type_url,
            "/cosmos.bank.v1beta1.MsgSend"
        );

        let actual = msg_queue.next().await.unwrap();

        assert_eq!(actual.as_ref().len(), 1);
        assert_eq!(actual.as_ref()[0].gas, gas_cost);
        assert_eq!(
            actual.as_ref()[0].msg.type_url,
            "/cosmos.bank.v1beta1.MsgSend"
        );
    }

    fn dummy_msg() -> Any {
        Any::from_msg(&MsgSend {
            from_address: TMAddress::random(PREFIX).to_string(),
            to_address: TMAddress::random(PREFIX).to_string(),
            amount: vec![],
        })
        .unwrap()
    }
}
