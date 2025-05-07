use std::ops::Mul;

use axelar_wasm_std::nonempty;
use cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse;
use cosmrs::tx::Fee;
use cosmrs::{Any, Coin, Gas};
use error_stack::{report, ResultExt};
use k256::sha2::{Digest, Sha256};
use num_traits::cast;
use report::{LoggableError, ResultCompatExt};
use thiserror::Error;
use tokio::sync::oneshot;
use tokio_stream::StreamExt;
use tracing::{error, info};
use typed_builder::TypedBuilder;
use valuable::Valuable;

use crate::broadcaster::dec_coin::DecCoin;
use crate::{cosmos, tofnd};

mod broadcaster;
mod msg_queue;
mod proto;

pub use broadcaster::Broadcaster;
#[cfg(test)]
pub use msg_queue::QueueMsg;
pub use msg_queue::{MsgQueue, MsgQueueClient};

type Result<T> = error_stack::Result<T, Error>;

#[derive(Error, Debug, Clone)]
pub enum Error {
    #[error("failed to enqueue message")]
    EnqueueMsg,
    #[error("failed to estimate gas")]
    EstimateGas,
    #[error("failed to adjust the fee")]
    FeeAdjustment,
    #[error("failed to query account")]
    AccountQuery,
    #[error("invalid public key")]
    InvalidPubKey,
    #[error("failed to sign tx")]
    SignTx,
    #[error("failed to broadcast tx")]
    BroadcastTx,
    #[error("failed to receive tx result")]
    ReceiveTxResult(#[from] oneshot::error::RecvError),
    #[error("message {msg_type}'s estimated gas {gas} exceeds gas limit {gas_cap}")]
    GasExceedsGasCap {
        msg_type: String,
        gas: Gas,
        gas_cap: Gas,
    },
}

/// A task that processes queued messages and broadcasts them to a Cosmos blockchain
///
/// `BroadcasterTask` continuously polls a message queue for batches of messages,
/// signs them using the provided signer, and broadcasts them to the Cosmos network.
/// It handles fee estimation, transaction creation, signing, and broadcasting.
///
/// The task is designed to be resilient to failures, continuing to process
/// new message batches even if previous ones fail. It provides feedback on
/// transaction results to message submitters through callback channels.
///
/// # Type Parameters
///
/// * `T` - A Cosmos client that can communicate with the blockchain
/// * `Q` - A Stream that yields batches of messages to be broadcast
/// * `S` - A cryptographic signer that can sign transaction payloads
#[derive(TypedBuilder)]
pub struct BroadcasterTask<T, Q, S>
where
    T: cosmos::CosmosClient,
    Q: futures::Stream<Item = nonempty::Vec<msg_queue::QueueMsg>> + Unpin,
    S: tofnd::grpc::Multisig,
{
    broadcaster: broadcaster::Broadcaster<T>,
    msg_queue: Q,
    signer: S,
    key_id: String,
    gas_adjustment: f64,
    gas_price: DecCoin,
}

impl<T, Q, S> BroadcasterTask<T, Q, S>
where
    T: cosmos::CosmosClient,
    Q: futures::Stream<Item = nonempty::Vec<msg_queue::QueueMsg>> + Unpin,
    S: tofnd::grpc::Multisig,
{
    /// Runs the broadcaster task until the message queue is exhausted
    ///
    /// This method continuously processes message batches from the queue:
    /// 1. Retrieves the next batch of messages from the queue
    /// 2. Broadcasts them as a single transaction
    /// 3. Handles the result (success or failure)
    /// 4. Notifies submitters of the transaction result via callbacks
    /// 5. Proceeds to the next batch
    ///
    /// The task runs until the message queue is closed/exhausted, at which point
    /// it terminates successfully. Errors during broadcasting are logged and
    /// communicated back to submitters but don't halt the task.
    ///
    /// # Returns
    ///
    /// A Result indicating whether the task completed successfully.
    /// Note that individual transaction failures don't cause the task to return an error.
    pub async fn run(mut self) -> Result<()> {
        while let Some(msgs) = self.msg_queue.next().await {
            let tx_hash = self
                .broadcast(msgs.as_ref().iter().map(|msg| msg.msg.clone()))
                .await
                .inspect(|res| {
                    info!(
                        tx_hash = res.txhash,
                        msg_count = msgs.as_ref().len(),
                        "successfully broadcasted tx"
                    );
                })
                .inspect_err(|err| {
                    error!(
                        err = LoggableError::from(err).as_value(),
                        "failed to broadcast tx",
                    );
                })
                .map(|res| res.txhash);

            handle_tx_res(tx_hash, msgs);
        }

        Ok(())
    }

    async fn estimate_fee(&mut self, batch_req: Any) -> Result<Fee> {
        let gas = self
            .broadcaster
            .estimate_gas(vec![batch_req])
            .await
            .change_context(Error::EstimateGas)?;
        let gas = gas as f64 * self.gas_adjustment;

        Ok(Fee::from_amount_and_gas(
            Coin::new(
                cast(gas.mul(self.gas_price.amount).ceil()).ok_or(report!(Error::FeeAdjustment))?,
                self.gas_price.denom.as_ref(),
            )
            .change_context(Error::FeeAdjustment)?,
            cast::<f64, u64>(gas).ok_or(report!(Error::FeeAdjustment))?,
        ))
    }

    async fn broadcast(&mut self, msgs: impl IntoIterator<Item = Any>) -> Result<TxResponse> {
        let batch_req = Any::from_msg(&proto::axelar::auxiliary::v1beta1::BatchRequest {
            sender: self.broadcaster.address.as_ref().to_bytes(),
            messages: msgs.into_iter().collect(),
        })
        .expect("failed to serialize proto message for batch request");
        let fee = self.estimate_fee(batch_req.clone()).await?;
        let pub_key = self.broadcaster.pub_key;

        self.broadcaster
            .broadcast(vec![batch_req], fee, |sign_doc| {
                let mut hasher = Sha256::new();
                hasher.update(sign_doc);

                let sign_digest: [u8; 32] = hasher
                    .finalize()
                    .to_vec()
                    .try_into()
                    .expect("hash size must be 32");

                self.signer.sign(
                    &self.key_id,
                    sign_digest.into(),
                    pub_key.into(),
                    tofnd::Algorithm::Ecdsa,
                )
            })
            .await
    }
}

fn handle_tx_res(tx_hash: Result<String>, msgs: nonempty::Vec<msg_queue::QueueMsg>) {
    Vec::from(msgs)
        .into_iter()
        .enumerate()
        .for_each(|(i, msg)| {
            match (msg.tx_res_callback, &tx_hash) {
                (tx_res_callback, Ok(tx_hash)) => {
                    let _ = tx_res_callback.send(Ok((tx_hash.clone(), i as u64)));
                }
                (tx_res_callback, Err(err)) => {
                    let _ = tx_res_callback.send(Err(report!(err.current_context().clone())));
                }
            };
        });
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::assert_err_contains;
    use cosmrs::proto::cosmos::auth::v1beta1::{BaseAccount, QueryAccountResponse};
    use cosmrs::proto::cosmos::base::abci::v1beta1::{GasInfo, TxResponse};
    use cosmrs::proto::cosmos::tx::v1beta1::{BroadcastTxResponse, Fee, SimulateResponse};
    use cosmrs::{tendermint, Any};
    use error_stack::report;
    use mockall::Sequence;
    use prost::Message;
    use tokio::sync::oneshot;
    use tokio_stream::iter;

    use crate::broadcaster::dec_coin::DecCoin;
    use crate::broadcaster_v2::msg_queue::QueueMsg;
    use crate::broadcaster_v2::{broadcaster, BroadcasterTask, Error};
    use crate::tofnd::error::Error as TofndError;
    use crate::tofnd::grpc::MockMultisig;
    use crate::types::{random_cosmos_public_key, TMAddress};
    use crate::{cosmos, PREFIX};

    fn dummy_msg() -> Any {
        Any {
            type_url: "/cosmos.bank.v1beta1.MsgSend".to_string(),
            value: vec![1, 2, 3],
        }
    }

    fn create_base_account(address: &TMAddress) -> BaseAccount {
        BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number: 42,
            sequence: 10,
        }
    }

    fn decode_gas_fee<R>(req: &R) -> Fee
    where
        R: AsRef<[u8]> + ?Sized,
    {
        let tx_raw = cosmrs::proto::cosmos::tx::v1beta1::TxRaw::decode(req.as_ref()).unwrap();

        cosmrs::proto::cosmos::tx::v1beta1::AuthInfo::decode(tx_raw.auth_info_bytes.as_slice())
            .unwrap()
            .fee
            .unwrap()
    }

    #[tokio::test]
    async fn broadcaster_task_should_process_message_queue_successfully() {
        let pub_key = random_cosmos_public_key();
        let address = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let base_account = create_base_account(&address);

        let (receivers, queue_msgs): (Vec<_>, Vec<_>) = (0..2)
            .map(|_| {
                let (tx, rx) = oneshot::channel();
                let msg = QueueMsg {
                    msg: dummy_msg(),
                    gas: 50000,
                    tx_res_callback: tx,
                };

                (rx, msg)
            })
            .unzip();
        let msg_queue = iter(vec![queue_msgs.try_into().unwrap()]);

        let mut mock_signer = MockMultisig::new();
        mock_signer
            .expect_sign()
            .once()
            .returning(|_, _, _, _| Ok(vec![0u8; 64]));

        let mut seq = Sequence::new();
        let mut mock_client = cosmos::MockCosmosClient::new();
        mock_client
            .expect_account()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(QueryAccountResponse {
                    account: Some(Any::from_msg(&base_account).unwrap()),
                })
            });
        mock_client
            .expect_simulate()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(SimulateResponse {
                    gas_info: Some(GasInfo {
                        gas_wanted: 0,
                        gas_used: 100000,
                    }),
                    result: None,
                })
            });
        mock_client
            .expect_broadcast_tx()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(BroadcastTxResponse {
                    tx_response: Some(TxResponse {
                        txhash: "tx_hash_success".to_string(),
                        code: 0,
                        ..Default::default()
                    }),
                })
            });

        let broadcaster = broadcaster::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .gas_adjustment(1.5)
            .gas_price(DecCoin::new(0.025, "uaxl").unwrap())
            .build();

        let result = tokio::spawn(async move { broadcaster_task.run().await })
            .await
            .unwrap();
        assert!(result.is_ok());

        for (i, rx) in receivers.into_iter().enumerate() {
            let (tx_hash, idx) = rx.await.unwrap().unwrap();

            assert_eq!(tx_hash, "tx_hash_success");
            assert_eq!(idx, i as u64);
        }
    }

    #[tokio::test]
    async fn broadcaster_task_should_handle_broadcast_errors() {
        let pub_key = random_cosmos_public_key();
        let address = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let initial_account = create_base_account(&address);
        let reset_account = create_base_account(&address);

        let (tx, rx) = oneshot::channel();
        let queue_msgs = vec![QueueMsg {
            msg: dummy_msg(),
            gas: 50000,
            tx_res_callback: tx,
        }]
        .try_into()
        .unwrap();
        let msg_queue = iter(vec![queue_msgs]);

        let mut mock_signer = MockMultisig::new();
        mock_signer
            .expect_sign()
            .once()
            .returning(|_, _, _, _| Ok(vec![0u8; 64]));

        let mut seq = Sequence::new();
        let mut mock_client = cosmos::MockCosmosClient::new();
        mock_client
            .expect_account()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(QueryAccountResponse {
                    account: Some(Any::from_msg(&initial_account).unwrap()),
                })
            });
        mock_client
            .expect_simulate()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(SimulateResponse {
                    gas_info: Some(GasInfo {
                        gas_wanted: 0,
                        gas_used: 100000,
                    }),
                    result: None,
                })
            });
        mock_client
            .expect_broadcast_tx()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| Err(report!(cosmos::Error::TxResponseMissing)));
        mock_client
            .expect_account()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(QueryAccountResponse {
                    account: Some(Any::from_msg(&reset_account).unwrap()),
                })
            });

        let broadcaster = broadcaster::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .gas_adjustment(1.5)
            .gas_price(DecCoin::new(0.025, "uaxl").unwrap())
            .build();

        let result = tokio::spawn(async move { broadcaster_task.run().await })
            .await
            .unwrap();
        assert!(result.is_ok());
        assert_err_contains!(rx.await.unwrap(), Error, Error::BroadcastTx);
    }

    #[tokio::test]
    async fn broadcaster_task_should_handle_signing_errors() {
        let pub_key = random_cosmos_public_key();
        let address = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let base_account = create_base_account(&address);

        let (tx, rx) = oneshot::channel();
        let queue_msgs = vec![QueueMsg {
            msg: dummy_msg(),
            gas: 50000,
            tx_res_callback: tx,
        }]
        .try_into()
        .unwrap();
        let msg_queue = iter(vec![queue_msgs]);

        let mut mock_signer = MockMultisig::new();
        mock_signer
            .expect_sign()
            .once()
            .returning(|_, _, _, _| Err(report!(TofndError::KeygenFailed)));

        let mut seq = Sequence::new();
        let mut mock_client = cosmos::MockCosmosClient::new();
        mock_client
            .expect_account()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(QueryAccountResponse {
                    account: Some(Any::from_msg(&base_account).unwrap()),
                })
            });
        mock_client
            .expect_simulate()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(SimulateResponse {
                    gas_info: Some(GasInfo {
                        gas_wanted: 0,
                        gas_used: 100000,
                    }),
                    result: None,
                })
            });

        let broadcaster = broadcaster::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .gas_adjustment(1.5)
            .gas_price(DecCoin::new(0.025, "uaxl").unwrap())
            .build();

        let result = tokio::spawn(async move { broadcaster_task.run().await })
            .await
            .unwrap();
        assert!(result.is_ok());
        assert_err_contains!(rx.await.unwrap(), Error, Error::SignTx);
    }

    #[tokio::test]
    async fn broadcaster_task_should_process_multiple_message_batches() {
        let pub_key = random_cosmos_public_key();
        let address = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let base_account = create_base_account(&address);

        let (tx_1, rx_1) = oneshot::channel();
        let (tx_2, rx_2) = oneshot::channel();
        let batch_1 = vec![QueueMsg {
            msg: dummy_msg(),
            gas: 50000,
            tx_res_callback: tx_1,
        }]
        .try_into()
        .unwrap();
        let batch_2 = vec![QueueMsg {
            msg: dummy_msg(),
            gas: 50000,
            tx_res_callback: tx_2,
        }]
        .try_into()
        .unwrap();
        let msg_queue = iter(vec![batch_1, batch_2]);

        let mut mock_signer = MockMultisig::new();
        mock_signer
            .expect_sign()
            .times(2)
            .returning(|_, _, _, _| Ok(vec![0u8; 64]));

        let mut seq = Sequence::new();
        let mut mock_client = cosmos::MockCosmosClient::new();
        mock_client
            .expect_account()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(QueryAccountResponse {
                    account: Some(Any::from_msg(&base_account).unwrap()),
                })
            });
        mock_client
            .expect_simulate()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(SimulateResponse {
                    gas_info: Some(GasInfo {
                        gas_wanted: 0,
                        gas_used: 100000,
                    }),
                    result: None,
                })
            });
        mock_client
            .expect_broadcast_tx()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(BroadcastTxResponse {
                    tx_response: Some(TxResponse {
                        txhash: "tx_hash_first_batch".to_string(),
                        code: 0,
                        ..Default::default()
                    }),
                })
            });
        mock_client
            .expect_simulate()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(SimulateResponse {
                    gas_info: Some(GasInfo {
                        gas_wanted: 0,
                        gas_used: 100000,
                    }),
                    result: None,
                })
            });
        mock_client
            .expect_broadcast_tx()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(BroadcastTxResponse {
                    tx_response: Some(TxResponse {
                        txhash: "tx_hash_second_batch".to_string(),
                        code: 0,
                        ..Default::default()
                    }),
                })
            });

        let broadcaster = broadcaster::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .gas_adjustment(1.5)
            .gas_price(DecCoin::new(0.025, "uaxl").unwrap())
            .build();

        let result = tokio::spawn(async move { broadcaster_task.run().await })
            .await
            .unwrap();
        assert!(result.is_ok());

        let (tx_hash, idx) = rx_1.await.unwrap().unwrap();
        assert_eq!(tx_hash, "tx_hash_first_batch");
        assert_eq!(idx, 0);

        let (tx_hash, idx) = rx_2.await.unwrap().unwrap();
        assert_eq!(tx_hash, "tx_hash_second_batch");
        assert_eq!(idx, 0);
    }

    #[tokio::test]
    async fn broadcaster_task_should_continue_after_broadcast_error() {
        let pub_key = random_cosmos_public_key();
        let address = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let initial_account = create_base_account(&address);
        let reset_account = create_base_account(&address);

        let (tx_1, rx_1) = oneshot::channel();
        let (tx_2, rx_2) = oneshot::channel();
        let batch_1 = vec![QueueMsg {
            msg: dummy_msg(),
            gas: 50000,
            tx_res_callback: tx_1,
        }]
        .try_into()
        .unwrap();
        let batch_2 = vec![QueueMsg {
            msg: dummy_msg(),
            gas: 50000,
            tx_res_callback: tx_2,
        }]
        .try_into()
        .unwrap();
        let msg_queue = iter(vec![batch_1, batch_2]);

        let mut mock_signer = MockMultisig::new();
        mock_signer
            .expect_sign()
            .times(2)
            .returning(|_, _, _, _| Ok(vec![0u8; 64]));

        let mut seq = Sequence::new();
        let mut mock_client = cosmos::MockCosmosClient::new();
        mock_client
            .expect_account()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(QueryAccountResponse {
                    account: Some(Any::from_msg(&initial_account).unwrap()),
                })
            });
        mock_client
            .expect_simulate()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(SimulateResponse {
                    gas_info: Some(GasInfo {
                        gas_wanted: 0,
                        gas_used: 100000,
                    }),
                    result: None,
                })
            });
        mock_client
            .expect_broadcast_tx()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| Err(report!(cosmos::Error::TxResponseMissing)));
        mock_client
            .expect_account()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(QueryAccountResponse {
                    account: Some(Any::from_msg(&reset_account).unwrap()),
                })
            });
        mock_client
            .expect_simulate()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(SimulateResponse {
                    gas_info: Some(GasInfo {
                        gas_wanted: 0,
                        gas_used: 100000,
                    }),
                    result: None,
                })
            });
        mock_client
            .expect_broadcast_tx()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(BroadcastTxResponse {
                    tx_response: Some(TxResponse {
                        txhash: "tx_hash_second_batch".to_string(),
                        code: 0,
                        ..Default::default()
                    }),
                })
            });

        let broadcaster = broadcaster::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .gas_adjustment(1.5)
            .gas_price(DecCoin::new(0.025, "uaxl").unwrap())
            .build();

        let result = tokio::spawn(async move { broadcaster_task.run().await })
            .await
            .unwrap();
        assert!(result.is_ok());

        let result = rx_1.await.unwrap();
        assert!(result.is_err());
        assert_err_contains!(result, Error, Error::BroadcastTx);

        let (tx_hash, idx) = rx_2.await.unwrap().unwrap();
        assert_eq!(tx_hash, "tx_hash_second_batch");
        assert_eq!(idx, 0);
    }

    #[tokio::test]
    async fn broadcaster_task_should_apply_gas_adjustment_and_gas_price() {
        let pub_key = random_cosmos_public_key();
        let address = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let gas_adjustment = 2.0;
        let gas_price_amount = 0.025;
        let expected_denom = "uaxl";
        let base_account = create_base_account(&address);
        let simulated_gas_used = 100000u64;
        let expected_gas_limit = 200000u64; // 100000 * 2 = 200000
        let expected_fee_amount = 5000u64; // 200000 * 0.025 = 5000

        let (tx, rx) = oneshot::channel();
        let queue_msgs = vec![QueueMsg {
            msg: dummy_msg(),
            gas: 50000,
            tx_res_callback: tx,
        }]
        .try_into()
        .unwrap();
        let msg_queue = iter(vec![queue_msgs]);

        let mut mock_signer = MockMultisig::new();
        mock_signer
            .expect_sign()
            .once()
            .returning(|_, _, _, _| Ok(vec![0u8; 64]));

        let mut seq = Sequence::new();
        let mut mock_client = cosmos::MockCosmosClient::new();
        mock_client
            .expect_account()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(QueryAccountResponse {
                    account: Some(Any::from_msg(&base_account).unwrap()),
                })
            });
        mock_client
            .expect_simulate()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(SimulateResponse {
                    gas_info: Some(GasInfo {
                        gas_wanted: 0,
                        gas_used: simulated_gas_used,
                    }),
                    result: None,
                })
            });
        mock_client
            .expect_broadcast_tx()
            .once()
            .in_sequence(&mut seq)
            .withf(move |req| {
                let actual_fee = decode_gas_fee(&req.tx_bytes);
                assert_eq!(actual_fee.amount.len(), 1);

                actual_fee.gas_limit == expected_gas_limit
                    && actual_fee.amount.first().unwrap().amount == expected_fee_amount.to_string()
                    && actual_fee.amount.first().unwrap().denom == expected_denom
            })
            .return_once(move |_| {
                Ok(BroadcastTxResponse {
                    tx_response: Some(TxResponse {
                        txhash: "tx_hash_success".to_string(),
                        gas_wanted: expected_gas_limit as i64,
                        gas_used: 95000,
                        code: 0,
                        ..Default::default()
                    }),
                })
            });

        let broadcaster = broadcaster::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, expected_denom).unwrap())
            .build();

        let result = tokio::spawn(async move { broadcaster_task.run().await })
            .await
            .unwrap();
        assert!(result.is_ok());

        let (tx_hash, idx) = rx.await.unwrap().unwrap();
        assert_eq!(tx_hash, "tx_hash_success");
        assert_eq!(idx, 0);
    }
}
