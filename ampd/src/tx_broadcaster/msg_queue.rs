use core::pin::Pin;
use core::task::{ready, Context, Poll};
use std::future::Future;

use cosmrs::{Any, Gas};
use error_stack::{report, ResultExt};
use futures::Stream;
use pin_project_lite::pin_project;
use report::ErrorExt;
use tokio::sync::{mpsc, oneshot};
use tokio::time;
use tokio_stream::adapters::Fuse;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;

use super::{Error, Result};
use crate::cosmos;
use crate::tx_broadcaster::account;

#[derive(Debug)]
pub struct Msg {
    pub msg: Any,
    pub gas: Gas,
    pub tx_res_callback: Option<oneshot::Sender<Result<(String, u64)>>>,
}

#[derive(Clone)]
pub struct MsgQueueClient<T, A>
where
    T: cosmos::CosmosClient,
    A: account::AccountManager,
{
    tx: mpsc::Sender<Msg>,
    cosmos_client: T,
    account_manager: A,
}

impl<T, A> MsgQueueClient<T, A>
where
    T: cosmos::CosmosClient,
    A: account::AccountManager,
{
    pub async fn enqueue_with_res(
        &mut self,
        msg: Any,
    ) -> Result<oneshot::Receiver<Result<(String, u64)>>> {
        let (tx, rx) = oneshot::channel();
        let msg = self.new_msg(msg, Some(tx)).await?;

        self.tx.send(msg).await.map_err(ErrorExt::into_report)?;

        Ok(rx)
    }

    pub async fn enqueue(&mut self, msg: Any) -> Result<()> {
        let msg = self.new_msg(msg, None).await?;

        self.tx.send(msg).await.map_err(ErrorExt::into_report)?;

        Ok(())
    }

    async fn new_msg(
        &mut self,
        msg: Any,
        tx_res_callback: Option<oneshot::Sender<Result<(String, u64)>>>,
    ) -> Result<Msg> {
        let sequence = self.account_manager.curr_sequence().await?;
        let gas = cosmos::estimate_gas(
            &mut self.cosmos_client,
            vec![msg.clone()],
            self.account_manager.pub_key(),
            sequence,
        )
        .await
        .change_context(Error::EstimateGas)?;
        let msg = Msg {
            msg,
            gas,
            tx_res_callback,
        };

        Ok(msg)
    }
}

pin_project! {
    pub struct MsgQueue {
        #[pin]
        stream: Fuse<ReceiverStream<Msg>>,
        #[pin]
        deadline: Option<time::Sleep>,
        queue: Queue,
        gas_capacity: Gas,
        duration: time::Duration,
    }
}

impl MsgQueue {
    pub fn new_msg_queue_and_client<T, A>(
        cosmos_client: T,
        account_manager: A,
        msg_cap: usize,
        gas_cap: Gas,
        duration: time::Duration,
    ) -> Result<(impl Stream<Item = Vec<Msg>>, MsgQueueClient<T, A>)>
    where
        T: cosmos::CosmosClient,
        A: account::AccountManager,
    {
        let (tx, rx) = mpsc::channel(msg_cap);

        Ok((
            Box::pin(MsgQueue {
                stream: ReceiverStream::new(rx).fuse(),
                deadline: None,
                queue: Queue::default(),
                gas_capacity: gas_cap,
                duration,
            }),
            MsgQueueClient {
                tx,
                cosmos_client,
                account_manager,
            },
        ))
    }
}

impl Stream for MsgQueue {
    type Item = Vec<Msg>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut me = self.as_mut().project();

        loop {
            match me.stream.as_mut().poll_next(cx) {
                Poll::Pending => break,
                Poll::Ready(Some(msg)) => {
                    if me.queue.is_empty() {
                        me.deadline.set(Some(time::sleep(*me.duration)));
                    }

                    // gas overflow
                    if me.queue.gas_cost().checked_add(msg.gas).is_none() {
                        let msgs = me.queue.pop_all();
                        me.queue.push(msg).expect("gas must not overflow");

                        return Poll::Ready(Some(msgs));
                    } else {
                        me.queue.push(msg).expect("gas must not overflow");
                    };

                    if me.queue.gas_cost() >= *me.gas_capacity {
                        return Poll::Ready(Some(me.queue.pop_all()));
                    }
                }
                Poll::Ready(None) => {
                    // Returning Some here is only correct because we fuse the inner stream.
                    let last = if me.queue.is_empty() {
                        None
                    } else {
                        Some(me.queue.pop_all())
                    };

                    return Poll::Ready(last);
                }
            }
        }

        if me.queue.is_empty() {
            return Poll::Pending;
        }

        if let Some(deadline) = me.deadline.as_pin_mut() {
            ready!(deadline.poll(cx));
        }

        Poll::Ready(Some(me.queue.pop_all()))
    }
}

#[derive(Default)]
struct Queue {
    msgs: Vec<Msg>,
    gas_cost: Gas,
}

impl Queue {
    pub fn push(&mut self, msg: Msg) -> Result<()> {
        self.gas_cost = self
            .gas_cost
            .checked_add(msg.gas)
            .ok_or(report!(Error::IntegerOverflow))?;
        self.msgs.push(msg);

        Ok(())
    }

    pub fn pop_all(&mut self) -> Vec<Msg> {
        self.gas_cost = 0;

        std::mem::take(&mut self.msgs)
    }

    pub fn gas_cost(&self) -> Gas {
        self.gas_cost
    }

    pub fn is_empty(&self) -> bool {
        self.msgs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::assert_err_contains;
    use cosmrs::proto::cosmos::bank::v1beta1::MsgSend;
    use cosmrs::proto::cosmos::base::abci::v1beta1::GasInfo;
    use cosmrs::proto::cosmos::tx::v1beta1::SimulateResponse;
    use cosmrs::tx::MessageExt;

    use super::*;
    use crate::{
        types::{random_cosmos_public_key, TMAddress},
        PREFIX,
    };

    #[tokio::test]
    async fn msg_queue_client_enqueue() {
        let gas_cap = 1000u64;

        let mut account_manager = account::MockAccountManager::new();
        account_manager.expect_curr_sequence().return_once(|| Ok(0));
        account_manager
            .expect_pub_key()
            .once()
            .return_const(random_cosmos_public_key());
        let mut cosmos_client = cosmos::MockCosmosClient::new();
        cosmos_client.expect_simulate().return_once(move |_| {
            Ok(SimulateResponse {
                gas_info: Some(GasInfo {
                    gas_wanted: gas_cap,
                    gas_used: gas_cap,
                }),
                result: None,
            })
        });

        let (mut msg_queue, mut msg_queue_client) = MsgQueue::new_msg_queue_and_client(
            cosmos_client,
            account_manager,
            10,
            gas_cap,
            time::Duration::from_secs(1),
        )
        .unwrap();

        msg_queue_client.enqueue(dummy_msg()).await.unwrap();
        let actual = msg_queue.next().await.unwrap();

        assert_eq!(actual.len(), 1);
        assert_eq!(actual[0].gas, gas_cap);
        assert_eq!(actual[0].msg.type_url, "/cosmos.bank.v1beta1.MsgSend");
        assert!(actual[0].tx_res_callback.is_none());
    }

    #[tokio::test]
    async fn msg_queue_client_enqueue_with_res() {
        let gas_cap = 1000u64;

        let mut account_manager = account::MockAccountManager::new();
        account_manager.expect_curr_sequence().return_once(|| Ok(0));
        account_manager
            .expect_pub_key()
            .once()
            .return_const(random_cosmos_public_key());
        let mut cosmos_client = cosmos::MockCosmosClient::new();
        cosmos_client.expect_simulate().return_once(move |_| {
            Ok(SimulateResponse {
                gas_info: Some(GasInfo {
                    gas_wanted: gas_cap,
                    gas_used: gas_cap,
                }),
                result: None,
            })
        });

        let (mut msg_queue, mut msg_queue_client) = MsgQueue::new_msg_queue_and_client(
            cosmos_client,
            account_manager,
            10,
            gas_cap,
            time::Duration::from_secs(1),
        )
        .unwrap();

        msg_queue_client
            .enqueue_with_res(dummy_msg())
            .await
            .unwrap();
        let actual = msg_queue.next().await.unwrap();

        assert_eq!(actual.len(), 1);
        assert_eq!(actual[0].gas, gas_cap);
        assert_eq!(actual[0].msg.type_url, "/cosmos.bank.v1beta1.MsgSend");
        assert!(actual[0].tx_res_callback.is_some());
    }

    #[tokio::test]
    async fn msg_queue_client_error_handling() {
        let mut account_manager = account::MockAccountManager::new();
        account_manager
            .expect_curr_sequence()
            .return_once(|| Err(report!(Error::QueryAccount)));
        let cosmos_client = cosmos::MockCosmosClient::new();
        let (_msg_queue, mut msg_queue_client) = MsgQueue::new_msg_queue_and_client(
            cosmos_client,
            account_manager,
            10,
            1000u64,
            time::Duration::from_secs(1),
        )
        .unwrap();

        assert_err_contains!(
            msg_queue_client.enqueue(dummy_msg()).await,
            Error,
            Error::QueryAccount
        );

        let mut account_manager = account::MockAccountManager::new();
        account_manager.expect_curr_sequence().return_once(|| Ok(0));
        account_manager
            .expect_pub_key()
            .once()
            .return_const(random_cosmos_public_key());
        let mut cosmos_client = cosmos::MockCosmosClient::new();
        cosmos_client.expect_simulate().return_once(move |_| {
            Ok(SimulateResponse {
                gas_info: None,
                result: None,
            })
        });
        let (_msg_queue, mut msg_queue_client) = MsgQueue::new_msg_queue_and_client(
            cosmos_client,
            account_manager,
            10,
            1000u64,
            time::Duration::from_secs(1),
        )
        .unwrap();

        assert_err_contains!(
            msg_queue_client.enqueue(dummy_msg()).await,
            Error,
            Error::EstimateGas
        );
    }

    #[tokio::test]
    async fn msg_queue_stream_timeout() {
        let gas_cap = 1000u64;

        let mut account_manager = account::MockAccountManager::new();
        account_manager.expect_curr_sequence().return_once(|| Ok(0));
        account_manager
            .expect_pub_key()
            .once()
            .return_const(random_cosmos_public_key());
        let mut cosmos_client = cosmos::MockCosmosClient::new();
        cosmos_client.expect_simulate().return_once(move |_| {
            Ok(SimulateResponse {
                gas_info: Some(GasInfo {
                    gas_wanted: gas_cap / 10,
                    gas_used: gas_cap / 10,
                }),
                result: None,
            })
        });

        let (mut msg_queue, mut msg_queue_client) = MsgQueue::new_msg_queue_and_client(
            cosmos_client,
            account_manager,
            10,
            gas_cap,
            time::Duration::from_secs(3),
        )
        .unwrap();

        msg_queue_client.enqueue(dummy_msg()).await.unwrap();
        let actual = msg_queue.next().await.unwrap();

        assert_eq!(actual.len(), 1);
        assert_eq!(actual[0].gas, gas_cap / 10);
        assert_eq!(actual[0].msg.type_url, "/cosmos.bank.v1beta1.MsgSend");
        assert!(actual[0].tx_res_callback.is_none());
    }

    #[tokio::test]
    async fn msg_queue_gas_capacity() {
        let gas_cap = 1000u64;
        let msg_count = 10;

        let mut account_manager = account::MockAccountManager::new();
        account_manager
            .expect_curr_sequence()
            .times(msg_count)
            .returning(|| Ok(0));
        account_manager
            .expect_pub_key()
            .times(msg_count)
            .return_const(random_cosmos_public_key());
        let mut cosmos_client = cosmos::MockCosmosClient::new();
        cosmos_client
            .expect_simulate()
            .times(msg_count)
            .returning(move |_| {
                Ok(SimulateResponse {
                    gas_info: Some(GasInfo {
                        gas_wanted: gas_cap / msg_count as u64,
                        gas_used: gas_cap / msg_count as u64,
                    }),
                    result: None,
                })
            });

        let (mut msg_queue, mut msg_queue_client) = MsgQueue::new_msg_queue_and_client(
            cosmos_client,
            account_manager,
            10,
            gas_cap,
            time::Duration::from_secs(3),
        )
        .unwrap();

        for _ in 0..msg_count {
            msg_queue_client.enqueue(dummy_msg()).await.unwrap();
        }
        let actual = msg_queue.next().await.unwrap();

        assert_eq!(actual.len(), msg_count);
        for msg in actual {
            assert_eq!(msg.gas, gas_cap / 10);
            assert_eq!(msg.msg.type_url, "/cosmos.bank.v1beta1.MsgSend");
            assert!(msg.tx_res_callback.is_none());
        }
    }

    #[tokio::test]
    async fn msg_queue_gas_overflow() {
        let gas_cap = u64::MAX;

        let mut account_manager = account::MockAccountManager::new();
        account_manager
            .expect_curr_sequence()
            .times(2)
            .returning(|| Ok(0));
        account_manager
            .expect_pub_key()
            .times(2)
            .return_const(random_cosmos_public_key());
        let mut cosmos_client = cosmos::MockCosmosClient::new();
        cosmos_client
            .expect_simulate()
            .times(2)
            .returning(move |_| {
                Ok(SimulateResponse {
                    gas_info: Some(GasInfo {
                        gas_wanted: gas_cap,
                        gas_used: gas_cap,
                    }),
                    result: None,
                })
            });

        let (mut msg_queue, mut msg_queue_client) = MsgQueue::new_msg_queue_and_client(
            cosmos_client,
            account_manager,
            10,
            gas_cap,
            time::Duration::from_secs(1),
        )
        .unwrap();

        msg_queue_client.enqueue(dummy_msg()).await.unwrap();
        msg_queue_client.enqueue(dummy_msg()).await.unwrap();
        let actual = msg_queue.next().await.unwrap();

        assert_eq!(actual.len(), 1);
        assert_eq!(actual[0].gas, gas_cap);
        assert_eq!(actual[0].msg.type_url, "/cosmos.bank.v1beta1.MsgSend");
        assert!(actual[0].tx_res_callback.is_none());

        let actual = msg_queue.next().await.unwrap();

        assert_eq!(actual.len(), 1);
        assert_eq!(actual[0].gas, gas_cap);
        assert_eq!(actual[0].msg.type_url, "/cosmos.bank.v1beta1.MsgSend");
        assert!(actual[0].tx_res_callback.is_none());
    }

    fn dummy_msg() -> Any {
        MsgSend {
            from_address: TMAddress::random(PREFIX).to_string(),
            to_address: TMAddress::random(PREFIX).to_string(),
            amount: vec![],
        }
        .to_any()
        .unwrap()
    }
}
