use core::pin::Pin;
use core::task::{Context, Poll};
use std::future::Future;

use axelar_wasm_std::nonempty;
use cosmrs::{Any, Gas};
use error_stack::bail;
use futures::{FutureExt, Stream};
use pin_project_lite::pin_project;
use report::ErrorExt;
use tokio::sync::{mpsc, oneshot};
use tokio::time;
use tokio_stream::adapters::Fuse;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;

use super::{broadcaster, Error, Result};
use crate::cosmos;

#[derive(Debug)]
pub struct QueueMsg {
    pub msg: Any,
    pub gas: Gas,
    pub tx_res_callback: oneshot::Sender<Result<(String, u64)>>,
}

#[derive(Clone)]
pub struct MsgQueueClient<T>
where
    T: cosmos::CosmosClient,
{
    tx: mpsc::Sender<QueueMsg>,
    broadcaster: broadcaster::Broadcaster<T>,
    gas_cap: Gas,
}

impl<T> MsgQueueClient<T>
where
    T: cosmos::CosmosClient,
{
    pub async fn enqueue(
        &mut self,
        msg: Any,
    ) -> Result<impl Future<Output = Result<(String, u64)>> + Send> {
        let rx = self.enqueue_with_channel(msg).await?;

        Ok(rx.map(|result| match result {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(err)) => Err(err),
            Err(err) => Err(err.into_report()),
        }))
    }

    pub async fn enqueue_and_forget(&mut self, msg: Any) -> Result<()> {
        let _ = self.enqueue_with_channel(msg).await?;

        Ok(())
    }

    async fn enqueue_with_channel(
        &mut self,
        msg: Any,
    ) -> Result<oneshot::Receiver<Result<(String, u64)>>> {
        let (tx, rx) = oneshot::channel();
        let gas = self
            .broadcaster
            .sim_cx()
            .await
            .estimate_gas(vec![msg.clone()])
            .await?;

        if gas > self.gas_cap {
            bail!(Error::GasExceedsGasCap {
                gas,
                gas_cap: self.gas_cap
            })
        }

        let msg = QueueMsg {
            msg,
            gas,
            tx_res_callback: tx,
        };

        self.tx.send(msg).await.map_err(ErrorExt::into_report)?;

        Ok(rx)
    }
}

pin_project! {
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
    pub fn new_msg_queue_and_client<T>(
        broadcaster: broadcaster::Broadcaster<T>,
        msg_cap: usize,
        gas_cap: Gas,
        duration: time::Duration,
    ) -> Result<(
        impl Stream<Item = nonempty::Vec<QueueMsg>>,
        MsgQueueClient<T>,
    )>
    where
        T: cosmos::CosmosClient,
    {
        let (tx, rx) = mpsc::channel(msg_cap);

        Ok((
            Box::pin(MsgQueue {
                stream: ReceiverStream::new(rx).fuse(),
                deadline: time::sleep(duration),
                queue: Queue::new(gas_cap),
                duration,
            }),
            MsgQueueClient {
                broadcaster,
                tx,
                gas_cap,
            },
        ))
    }
}

impl Stream for MsgQueue {
    type Item = nonempty::Vec<QueueMsg>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut me = self.as_mut().project();

        loop {
            match me.stream.as_mut().poll_next(cx) {
                Poll::Pending => break,
                Poll::Ready(Some(msg)) => {
                    if me.queue.is_empty() {
                        me.deadline.set(time::sleep(*me.duration));
                    }

                    if let Some(msgs) = me.queue.push(msg) {
                        return Poll::Ready(Some(msgs));
                    }
                }
                Poll::Ready(None) => {
                    // after the client stream was terminated, the MsgQueue must be fully drained before it can also terminate
                    return Poll::Ready(me.queue.pop_all());
                }
            }
        }

        if me.queue.is_empty() {
            return Poll::Pending;
        }

        match me.deadline.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => Poll::Ready(me.queue.pop_all()),
        }
    }
}

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

    pub fn push(&mut self, msg: QueueMsg) -> Option<nonempty::Vec<QueueMsg>> {
        match self.gas_cost.checked_add(msg.gas) {
            None => {
                let results = self.pop_all();

                self.gas_cost = msg.gas;
                self.msgs.push(msg);

                results
            }
            Some(gas_cost) if gas_cost > self.gas_cap => {
                let results = self.pop_all();

                self.gas_cost = msg.gas;
                self.msgs.push(msg);

                results
            }
            Some(gas_cost) if gas_cost == self.gas_cap => {
                let results = if let Some(mut results) = self.pop_all() {
                    results.as_mut().push(msg);

                    results
                } else {
                    vec![msg].try_into().expect("must not be empty")
                };

                Some(results)
            }
            Some(gas_cost) => {
                self.gas_cost = gas_cost;
                self.msgs.push(msg);

                None
            }
        }
    }

    pub fn pop_all(&mut self) -> Option<nonempty::Vec<QueueMsg>> {
        if self.is_empty() {
            return None;
        }

        self.gas_cost = 0;

        Some(
            std::mem::take(&mut self.msgs)
                .try_into()
                .expect("msgs must not be empty"),
        )
    }

    pub fn is_empty(&self) -> bool {
        self.msgs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::assert_err_contains;
    use cosmrs::proto::cosmos::auth::v1beta1::{BaseAccount, QueryAccountResponse};
    use cosmrs::proto::cosmos::bank::v1beta1::MsgSend;
    use cosmrs::proto::cosmos::base::abci::v1beta1::GasInfo;
    use cosmrs::proto::cosmos::tx::v1beta1::SimulateResponse;

    use super::*;
    use crate::broadcaster_v2::Error;
    use crate::types::{random_cosmos_public_key, TMAddress};
    use crate::PREFIX;

    #[tokio::test]
    async fn msg_queue_client_enqueue_and_forget() {
        let gas_cap = 1000u64;
        let base_account = BaseAccount {
            address: TMAddress::random(PREFIX).to_string(),
            pub_key: None,
            account_number: 42,
            sequence: 10,
        };

        let mut cosmos_client = cosmos::MockCosmosClient::new();
        cosmos_client.expect_account().return_once(move |_| {
            Ok(QueryAccountResponse {
                account: Some(Any::from_msg(&base_account).unwrap()),
            })
        });
        cosmos_client.expect_simulate().return_once(move |_| {
            Ok(SimulateResponse {
                gas_info: Some(GasInfo {
                    gas_wanted: gas_cap,
                    gas_used: gas_cap,
                }),
                result: None,
            })
        });
        let broadcaster = broadcaster::Broadcaster::new(
            cosmos_client,
            "chain-id".parse().unwrap(),
            random_cosmos_public_key(),
        )
        .await
        .unwrap();

        let (mut msg_queue, mut msg_queue_client) = MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            gas_cap,
            time::Duration::from_secs(1),
        )
        .unwrap();

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
    }

    #[tokio::test]
    async fn msg_queue_client_enqueue() {
        let gas_cap = 1000u64;
        let base_account = BaseAccount {
            address: TMAddress::random(PREFIX).to_string(),
            pub_key: None,
            account_number: 42,
            sequence: 10,
        };

        let mut cosmos_client = cosmos::MockCosmosClient::new();
        cosmos_client.expect_account().return_once(move |_| {
            Ok(QueryAccountResponse {
                account: Some(Any::from_msg(&base_account).unwrap()),
            })
        });
        cosmos_client.expect_simulate().return_once(move |_| {
            Ok(SimulateResponse {
                gas_info: Some(GasInfo {
                    gas_wanted: gas_cap,
                    gas_used: gas_cap,
                }),
                result: None,
            })
        });
        let broadcaster = broadcaster::Broadcaster::new(
            cosmos_client,
            "chain-id".parse().unwrap(),
            random_cosmos_public_key(),
        )
        .await
        .unwrap();

        let (mut msg_queue, mut msg_queue_client) = MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            gas_cap,
            time::Duration::from_secs(1),
        )
        .unwrap();

        let _ = msg_queue_client.enqueue(dummy_msg()).await.unwrap();
        let actual = msg_queue.next().await.unwrap();

        assert_eq!(actual.as_ref().len(), 1);
        assert_eq!(actual.as_ref()[0].gas, gas_cap);
        assert_eq!(
            actual.as_ref()[0].msg.type_url,
            "/cosmos.bank.v1beta1.MsgSend"
        );
    }

    #[tokio::test]
    async fn msg_queue_client_error_handling() {
        let base_account = BaseAccount {
            address: TMAddress::random(PREFIX).to_string(),
            pub_key: None,
            account_number: 42,
            sequence: 10,
        };

        let mut cosmos_client = cosmos::MockCosmosClient::new();
        cosmos_client.expect_account().return_once(move |_| {
            Ok(QueryAccountResponse {
                account: Some(Any::from_msg(&base_account).unwrap()),
            })
        });
        cosmos_client.expect_simulate().return_once(move |_| {
            Ok(SimulateResponse {
                gas_info: None,
                result: None,
            })
        });
        let broadcaster = broadcaster::Broadcaster::new(
            cosmos_client,
            "chain-id".parse().unwrap(),
            random_cosmos_public_key(),
        )
        .await
        .unwrap();

        let (_msg_queue, mut msg_queue_client) = MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            1000u64,
            time::Duration::from_secs(1),
        )
        .unwrap();

        assert_err_contains!(
            msg_queue_client.enqueue_and_forget(dummy_msg()).await,
            Error,
            Error::EstimateGas
        );
    }

    #[tokio::test]
    async fn msg_queue_stream_timeout() {
        let gas_cap = 1000u64;
        let base_account = BaseAccount {
            address: TMAddress::random(PREFIX).to_string(),
            pub_key: None,
            account_number: 42,
            sequence: 10,
        };

        let mut cosmos_client = cosmos::MockCosmosClient::new();
        cosmos_client.expect_account().return_once(move |_| {
            Ok(QueryAccountResponse {
                account: Some(Any::from_msg(&base_account).unwrap()),
            })
        });
        cosmos_client.expect_simulate().return_once(move |_| {
            Ok(SimulateResponse {
                gas_info: Some(GasInfo {
                    gas_wanted: gas_cap / 10,
                    gas_used: gas_cap / 10,
                }),
                result: None,
            })
        });
        let broadcaster = broadcaster::Broadcaster::new(
            cosmos_client,
            "chain-id".parse().unwrap(),
            random_cosmos_public_key(),
        )
        .await
        .unwrap();

        let (mut msg_queue, mut msg_queue_client) = MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            gas_cap,
            time::Duration::from_secs(3),
        )
        .unwrap();

        msg_queue_client
            .enqueue_and_forget(dummy_msg())
            .await
            .unwrap();
        let actual = msg_queue.next().await.unwrap();

        assert_eq!(actual.as_ref().len(), 1);
        assert_eq!(actual.as_ref()[0].gas, gas_cap / 10);
        assert_eq!(
            actual.as_ref()[0].msg.type_url,
            "/cosmos.bank.v1beta1.MsgSend"
        );
    }

    #[tokio::test]
    async fn msg_queue_gas_capacity() {
        let gas_cap = 1000u64;
        let msg_count = 10;
        let base_account = BaseAccount {
            address: TMAddress::random(PREFIX).to_string(),
            pub_key: None,
            account_number: 42,
            sequence: 10,
        };

        let mut cosmos_client = cosmos::MockCosmosClient::new();
        cosmos_client.expect_account().return_once(move |_| {
            Ok(QueryAccountResponse {
                account: Some(Any::from_msg(&base_account).unwrap()),
            })
        });
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
        let broadcaster = broadcaster::Broadcaster::new(
            cosmos_client,
            "chain-id".parse().unwrap(),
            random_cosmos_public_key(),
        )
        .await
        .unwrap();

        let (mut msg_queue, mut msg_queue_client) = MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            gas_cap,
            time::Duration::from_secs(3),
        )
        .unwrap();

        for _ in 0..msg_count {
            msg_queue_client
                .enqueue_and_forget(dummy_msg())
                .await
                .unwrap();
        }
        let actual = msg_queue.next().await.unwrap();

        assert_eq!(actual.as_ref().len(), msg_count);
        for msg in actual.as_ref() {
            assert_eq!(msg.gas, gas_cap / 10);
            assert_eq!(msg.msg.type_url, "/cosmos.bank.v1beta1.MsgSend");
        }
    }

    #[tokio::test]
    async fn msg_queue_gas_overflow() {
        let gas_cap = u64::MAX;
        let base_account = BaseAccount {
            address: TMAddress::random(PREFIX).to_string(),
            pub_key: None,
            account_number: 42,
            sequence: 10,
        };

        let mut cosmos_client = cosmos::MockCosmosClient::new();
        cosmos_client.expect_account().return_once(move |_| {
            Ok(QueryAccountResponse {
                account: Some(Any::from_msg(&base_account).unwrap()),
            })
        });
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
        let broadcaster = broadcaster::Broadcaster::new(
            cosmos_client,
            "chain-id".parse().unwrap(),
            random_cosmos_public_key(),
        )
        .await
        .unwrap();

        let (mut msg_queue, mut msg_queue_client) = MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            gas_cap,
            time::Duration::from_secs(1),
        )
        .unwrap();

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
        assert_eq!(actual.as_ref()[0].gas, gas_cap);
        assert_eq!(
            actual.as_ref()[0].msg.type_url,
            "/cosmos.bank.v1beta1.MsgSend"
        );

        let actual = msg_queue.next().await.unwrap();

        assert_eq!(actual.as_ref().len(), 1);
        assert_eq!(actual.as_ref()[0].gas, gas_cap);
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
