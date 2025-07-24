use std::fmt::Debug;
use std::sync::Arc;

use axelar_wasm_std::nonempty;
use cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse;
use cosmrs::{Any, Coin, Gas};
use error_stack::ResultExt;
use k256::sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::oneshot;
use tokio_stream::StreamExt;
use tracing::{error, info, instrument};
use typed_builder::TypedBuilder;

use crate::types::TMAddress;
use crate::{cosmos, tofnd};

mod broadcaster;
mod config;
mod confirmer;
mod dec_coin;
mod msg_queue;
mod proto;
mod tx;

pub use broadcaster::Broadcaster;
pub use config::Config;
pub use confirmer::{confirm_tx, TxConfirmer};
#[cfg(test)]
pub use dec_coin::DecCoin;
#[cfg(test)]
pub use msg_queue::QueueMsg;
pub use msg_queue::{MsgQueue, MsgQueueClient};
pub use tx::Tx;

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
    #[error("failed to query balance")]
    BalanceQuery,
    #[error("insufficient balance: address {address} has {balance}")]
    InsufficientBalance { address: TMAddress, balance: Coin },
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
    #[error("failed to confirm tx {0}")]
    ConfirmTx(String),
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
#[derive(Debug, TypedBuilder)]
pub struct BroadcasterTask<T, Q, S>
where
    T: cosmos::CosmosClient,
    Q: futures::Stream<Item = nonempty::Vec<msg_queue::QueueMsg>> + Unpin + Debug,
    S: tofnd::Multisig,
{
    broadcaster: broadcaster::Broadcaster<T>,
    msg_queue: Q,
    signer: S,
    key_id: String,
    #[builder(default = None, setter(strip_option))]
    tx_confirmer_client: Option<confirmer::TxConfirmerClient>,
}

impl<T, Q, S> BroadcasterTask<T, Q, S>
where
    T: cosmos::CosmosClient + Debug,
    Q: futures::Stream<Item = nonempty::Vec<msg_queue::QueueMsg>> + Unpin + Debug,
    S: tofnd::Multisig + Debug,
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
    #[instrument(skip_all)]
    pub async fn run(mut self) -> Result<()> {
        while let Some(msgs) = self.msg_queue.next().await {
            let tx_hash = self
                .broadcast(
                    msgs.as_ref()
                        .iter()
                        .map(|msg| msg.msg.clone())
                        .collect::<Vec<_>>()
                        .try_into()
                        .expect("msgs cannot be empty"),
                )
                .await
                .map(|res| res.txhash);

            self.handle_tx_res(tx_hash, msgs).await?;
        }

        Ok(())
    }

    /// Broadcasts a collection of messages as a single transaction to the Cosmos blockchain.
    ///
    /// This method handles the complete transaction lifecycle:
    /// 1. Packages messages into a BatchRequest
    /// 2. Estimates appropriate gas and fee based on simulation
    /// 3. Signs the transaction using the configured signer
    /// 4. Broadcasts the signed transaction to the network
    /// 5. Logs the results of the broadcast operation
    ///
    /// The gas calculation applies the configured gas adjustment factor to the
    /// simulated gas, and calculates fees based on the gas price denomination.
    ///
    /// # Parameters
    /// * `msgs` - A non-empty vector of Any-encoded protocol messages to broadcast
    ///
    /// # Returns
    /// * On success: TxResponse containing the transaction hash and execution results
    /// * On failure: Error indicating what part of the broadcast process failed
    ///
    /// # Errors
    /// This method can fail with various error types depending on where in the process it fails:
    /// * `Error::EstimateGas` - If the gas estimation simulation fails
    /// * `Error::FeeAdjustment` - If fee calculation encounters numeric conversion issues
    /// * `Error::SignTx` - If transaction signing fails
    /// * `Error::BroadcastTx` - If the network rejects the transaction
    #[instrument(skip_all)]
    pub async fn broadcast(&mut self, msgs: nonempty::Vec<Any>) -> Result<TxResponse> {
        let msgs: Vec<_> = msgs.into();
        let msg_count = msgs.len();
        info!(msg_count, "broadcasting messages");

        let batch_req = Any::from_msg(&proto::axelar::auxiliary::v1beta1::BatchRequest {
            sender: self.broadcaster.address.as_ref().to_bytes(),
            messages: msgs,
        })
        .expect("failed to serialize proto message for batch request");
        let pub_key = self.broadcaster.pub_key;

        self.broadcaster
            .broadcast(vec![batch_req], |sign_doc| {
                let mut hasher = Sha256::new();
                hasher.update(sign_doc);

                let sign_digest: [u8; 32] = hasher
                    .finalize()
                    .to_vec()
                    .try_into()
                    .expect("hash size must be 32");

                self.signer.sign(
                    &self.key_id,
                    sign_digest,
                    pub_key.into(),
                    tofnd::Algorithm::Ecdsa,
                )
            })
            .await
            .inspect(|res| {
                info!(
                    tx_hash = res.txhash,
                    msg_count, "successfully broadcasted tx"
                );
            })
    }

    #[instrument(skip(self))]
    async fn handle_tx_res(
        &self,
        tx_hash: Result<String>,
        msgs: nonempty::Vec<msg_queue::QueueMsg>,
    ) -> Result<()> {
        if let (Some(confirmer), Ok(tx_hash)) = (&self.tx_confirmer_client, &tx_hash) {
            confirmer
                .send(tx_hash.clone())
                .await
                .change_context(Error::ConfirmTx(tx_hash.clone()))?;
        }

        let tx_hash = tx_hash.map_err(Arc::new);

        Vec::from(msgs)
            .into_iter()
            .enumerate()
            .for_each(|(i, msg)| {
                match &tx_hash {
                    Ok(tx_hash) => {
                        let _ = msg.tx_res_callback.send(Ok((tx_hash.clone(), i as u64)));
                    }
                    Err(err) => {
                        let _ = msg.tx_res_callback.send(Err(err.clone()));
                    }
                };
            });

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use cosmos_sdk_proto::cosmos::auth::v1beta1::BaseAccount;
    use cosmrs::proto::cosmos::tx::v1beta1::Fee;
    use prost::Message;

    use crate::types::TMAddress;

    pub fn create_base_account(address: &TMAddress) -> BaseAccount {
        BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number: 42,
            sequence: 10,
        }
    }

    pub fn decode_gas_fee<R>(req: &R) -> Fee
    where
        R: AsRef<[u8]> + ?Sized,
    {
        let tx_raw = cosmrs::proto::cosmos::tx::v1beta1::TxRaw::decode(req.as_ref()).unwrap();

        cosmrs::proto::cosmos::tx::v1beta1::AuthInfo::decode(tx_raw.auth_info_bytes.as_slice())
            .unwrap()
            .fee
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::{assert_err_contains, err_contains};
    use cosmos_sdk_proto::cosmos::base::v1beta1::Coin;
    use cosmrs::proto::cosmos::auth::v1beta1::QueryAccountResponse;
    use cosmrs::proto::cosmos::bank::v1beta1::{QueryBalanceRequest, QueryBalanceResponse};
    use cosmrs::proto::cosmos::base::abci::v1beta1::{GasInfo, TxResponse};
    use cosmrs::proto::cosmos::tx::v1beta1::{BroadcastTxResponse, SimulateResponse};
    use cosmrs::{tendermint, Any};
    use error_stack::report;
    use futures::StreamExt;
    use mockall::{predicate, Sequence};
    use tokio::sync::{mpsc, oneshot};
    use tokio_stream::wrappers::ReceiverStream;
    use tokio_stream::{empty, iter};

    use crate::broadcaster_v2::dec_coin::DecCoin;
    use crate::broadcaster_v2::msg_queue::QueueMsg;
    use crate::broadcaster_v2::test_utils::{create_base_account, decode_gas_fee};
    use crate::broadcaster_v2::{broadcaster, BroadcasterTask, Error};
    use crate::tofnd::{self, MockMultisig};
    use crate::types::random_cosmos_public_key;
    use crate::{cosmos, PREFIX};

    fn dummy_msg() -> Any {
        Any {
            type_url: "/cosmos.bank.v1beta1.MsgSend".to_string(),
            value: vec![1, 2, 3],
        }
    }

    #[tokio::test]
    async fn broadcaster_task_should_process_message_queue_successfully_and_send_for_confirmation()
    {
        let pub_key = random_cosmos_public_key();
        let address = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let base_account = create_base_account(&address);
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";

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
            .expect_balance()
            .once()
            .with(predicate::eq(QueryBalanceRequest {
                address: address.to_string(),
                denom: "uaxl".to_string(),
            }))
            .in_sequence(&mut seq)
            .return_once(|_| {
                Ok(QueryBalanceResponse {
                    balance: Some(Coin {
                        denom: "uaxl".to_string(),
                        amount: "1000000".to_string(),
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
                        txhash: "tx_hash_success".to_string(),
                        code: 0,
                        ..Default::default()
                    }),
                })
            });

        let broadcaster = broadcaster::Broadcaster::builder()
            .client(mock_client)
            .chain_id(chain_id)
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();
        let (tx, rx) = mpsc::channel(1);
        let broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .tx_confirmer_client(tx)
            .build();

        let result = tokio::spawn(async move { broadcaster_task.run().await })
            .await
            .unwrap();
        assert!(result.is_ok());
        assert_eq!(
            vec!["tx_hash_success".to_string()],
            ReceiverStream::new(rx).collect::<Vec<_>>().await
        );

        for (i, rx) in receivers.into_iter().enumerate() {
            let (tx_hash, idx) = rx.await.unwrap().unwrap();

            assert_eq!(tx_hash, "tx_hash_success");
            assert_eq!(idx, i as u64);
        }
    }

    #[tokio::test]
    async fn broadcaster_task_should_process_message_queue_successfully() {
        let pub_key = random_cosmos_public_key();
        let address = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let base_account = create_base_account(&address);
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";

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
            .expect_balance()
            .once()
            .with(predicate::eq(QueryBalanceRequest {
                address: address.to_string(),
                denom: "uaxl".to_string(),
            }))
            .in_sequence(&mut seq)
            .return_once(|_| {
                Ok(QueryBalanceResponse {
                    balance: Some(Coin {
                        denom: "uaxl".to_string(),
                        amount: "1000000".to_string(),
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
                        txhash: "tx_hash_success".to_string(),
                        code: 0,
                        ..Default::default()
                    }),
                })
            });

        let broadcaster = broadcaster::Broadcaster::builder()
            .client(mock_client)
            .chain_id(chain_id)
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();
        let broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
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
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";

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
            .expect_balance()
            .once()
            .with(predicate::eq(QueryBalanceRequest {
                address: address.to_string(),
                denom: "uaxl".to_string(),
            }))
            .in_sequence(&mut seq)
            .return_once(|_| {
                Ok(QueryBalanceResponse {
                    balance: Some(Coin {
                        denom: "uaxl".to_string(),
                        amount: "1000000".to_string(),
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

        let broadcaster = broadcaster::Broadcaster::builder()
            .client(mock_client)
            .chain_id(chain_id)
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();
        let broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .build();

        let result = tokio::spawn(async move { broadcaster_task.run().await })
            .await
            .unwrap();
        assert!(result.is_ok());

        let err = rx.await.unwrap().unwrap_err();
        assert!(err_contains!(err.as_ref(), Error, Error::BroadcastTx));
    }

    #[tokio::test]
    async fn broadcaster_task_should_handle_signing_errors() {
        let pub_key = random_cosmos_public_key();
        let address = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let base_account = create_base_account(&address);
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";

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
            .returning(|_, _, _, _| Err(report!(tofnd::Error::InvalidKeygenResponse)));

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
            .expect_balance()
            .once()
            .with(predicate::eq(QueryBalanceRequest {
                address: address.to_string(),
                denom: "uaxl".to_string(),
            }))
            .in_sequence(&mut seq)
            .return_once(|_| {
                Ok(QueryBalanceResponse {
                    balance: Some(Coin {
                        denom: "uaxl".to_string(),
                        amount: "1000000".to_string(),
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

        let broadcaster = broadcaster::Broadcaster::builder()
            .client(mock_client)
            .chain_id(chain_id)
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();
        let broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .build();

        let result = tokio::spawn(async move { broadcaster_task.run().await })
            .await
            .unwrap();
        assert!(result.is_ok());

        let err = rx.await.unwrap().unwrap_err();
        assert!(err_contains!(err.as_ref(), Error, Error::SignTx));
    }

    #[tokio::test]
    async fn broadcaster_task_should_process_multiple_message_batches() {
        let pub_key = random_cosmos_public_key();
        let address = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let base_account = create_base_account(&address);
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";

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
            .expect_balance()
            .once()
            .with(predicate::eq(QueryBalanceRequest {
                address: address.to_string(),
                denom: "uaxl".to_string(),
            }))
            .in_sequence(&mut seq)
            .return_once(|_| {
                Ok(QueryBalanceResponse {
                    balance: Some(Coin {
                        denom: "uaxl".to_string(),
                        amount: "1000000".to_string(),
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

        let broadcaster = broadcaster::Broadcaster::builder()
            .client(mock_client)
            .chain_id(chain_id)
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();
        let broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
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
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";

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
            .expect_balance()
            .once()
            .with(predicate::eq(QueryBalanceRequest {
                address: address.to_string(),
                denom: "uaxl".to_string(),
            }))
            .in_sequence(&mut seq)
            .return_once(|_| {
                Ok(QueryBalanceResponse {
                    balance: Some(Coin {
                        denom: "uaxl".to_string(),
                        amount: "1000000".to_string(),
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

        let broadcaster = broadcaster::Broadcaster::builder()
            .client(mock_client)
            .chain_id(chain_id)
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();
        let broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .build();

        let result = tokio::spawn(async move { broadcaster_task.run().await })
            .await
            .unwrap();
        assert!(result.is_ok());

        let result = rx_1.await.unwrap();
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err_contains!(err.as_ref(), Error, Error::BroadcastTx));

        let (tx_hash, idx) = rx_2.await.unwrap().unwrap();
        assert_eq!(tx_hash, "tx_hash_second_batch");
        assert_eq!(idx, 0);
    }

    #[tokio::test]
    async fn broadcast_should_successfully_broadcast_single_message() {
        let pub_key = random_cosmos_public_key();
        let address = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";
        let base_account = create_base_account(&address);
        let simulated_gas_used = 100000u64;
        let expected_gas_limit = 150000u64; // 100000 * 1.5 = 150000
        let expected_fee_amount = 3750u64; // 150000 * 0.025 = 3750

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
            .expect_balance()
            .once()
            .with(predicate::eq(QueryBalanceRequest {
                address: address.to_string(),
                denom: gas_price_denom.to_string(),
            }))
            .in_sequence(&mut seq)
            .return_once(|_| {
                Ok(QueryBalanceResponse {
                    balance: Some(Coin {
                        denom: gas_price_denom.to_string(),
                        amount: "1000000".to_string(),
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
                    && actual_fee.amount.first().unwrap().denom == gas_price_denom
            })
            .return_once(move |_| {
                Ok(BroadcastTxResponse {
                    tx_response: Some(TxResponse {
                        txhash: "tx_hash_success".to_string(),
                        code: 0,
                        ..Default::default()
                    }),
                })
            });

        let broadcaster = broadcaster::Broadcaster::builder()
            .client(mock_client)
            .chain_id(chain_id)
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();
        let msg_queue = empty();
        let mut broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .build();

        let messages = vec![dummy_msg()].try_into().unwrap();
        let result = broadcaster_task.broadcast(messages).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.txhash, "tx_hash_success");
        assert_eq!(response.code, 0);
    }

    #[tokio::test]
    async fn broadcast_should_successfully_broadcast_multiple_messages() {
        let pub_key = random_cosmos_public_key();
        let address = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";
        let base_account = create_base_account(&address);
        let simulated_gas_used = 100000u64;

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
            .expect_balance()
            .once()
            .with(predicate::eq(QueryBalanceRequest {
                address: address.to_string(),
                denom: gas_price_denom.to_string(),
            }))
            .in_sequence(&mut seq)
            .return_once(|_| {
                Ok(QueryBalanceResponse {
                    balance: Some(Coin {
                        denom: gas_price_denom.to_string(),
                        amount: "1000000".to_string(),
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
                        gas_used: simulated_gas_used,
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
                        txhash: "tx_hash_multiple_msgs".to_string(),
                        code: 0,
                        ..Default::default()
                    }),
                })
            });

        let broadcaster = broadcaster::Broadcaster::builder()
            .client(mock_client)
            .chain_id(chain_id)
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();
        let msg_queue = empty();
        let mut broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .build();

        let messages = vec![dummy_msg(), dummy_msg(), dummy_msg()]
            .try_into()
            .unwrap();
        let result = broadcaster_task.broadcast(messages).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.txhash, "tx_hash_multiple_msgs");
        assert_eq!(response.code, 0);
    }

    #[tokio::test]
    async fn broadcast_should_propagate_gas_estimation_error() {
        let pub_key = random_cosmos_public_key();
        let address = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";
        let base_account = create_base_account(&address);

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
            .expect_balance()
            .once()
            .with(predicate::eq(QueryBalanceRequest {
                address: address.to_string(),
                denom: gas_price_denom.to_string(),
            }))
            .in_sequence(&mut seq)
            .return_once(|_| {
                Ok(QueryBalanceResponse {
                    balance: Some(Coin {
                        denom: gas_price_denom.to_string(),
                        amount: "1000000".to_string(),
                    }),
                })
            });
        mock_client
            .expect_simulate()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Err(report!(cosmos::Error::GrpcRequest(
                    tonic::Status::internal("simulation failed")
                )))
            });

        let broadcaster = broadcaster::Broadcaster::builder()
            .client(mock_client)
            .chain_id(chain_id)
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();
        let msg_queue = empty();
        let mut broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(MockMultisig::new())
            .key_id("test-key".to_string())
            .build();

        let messages = vec![dummy_msg()].try_into().unwrap();
        let result = broadcaster_task.broadcast(messages).await;
        assert!(result.is_err());
        assert_err_contains!(result, Error, Error::EstimateGas);
    }

    #[tokio::test]
    async fn broadcast_should_propagate_signing_error() {
        let pub_key = random_cosmos_public_key();
        let address = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";
        let base_account = create_base_account(&address);
        let simulated_gas_used = 100000u64;

        let mut mock_signer = MockMultisig::new();
        mock_signer
            .expect_sign()
            .once()
            .returning(|_, _, _, _| Err(report!(tofnd::Error::InvalidSignResponse)));

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
            .expect_balance()
            .once()
            .with(predicate::eq(QueryBalanceRequest {
                address: address.to_string(),
                denom: gas_price_denom.to_string(),
            }))
            .in_sequence(&mut seq)
            .return_once(|_| {
                Ok(QueryBalanceResponse {
                    balance: Some(Coin {
                        denom: gas_price_denom.to_string(),
                        amount: "1000000".to_string(),
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
                        gas_used: simulated_gas_used,
                    }),
                    result: None,
                })
            });

        let broadcaster = broadcaster::Broadcaster::builder()
            .client(mock_client)
            .chain_id(chain_id)
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();
        let msg_queue = empty();
        let mut broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .build();

        let messages = vec![dummy_msg()].try_into().unwrap();
        let result = broadcaster_task.broadcast(messages).await;
        assert!(result.is_err());
        assert_err_contains!(result, Error, Error::SignTx);
    }

    #[tokio::test]
    async fn broadcast_should_propagate_broadcast_error() {
        let pub_key = random_cosmos_public_key();
        let address = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";
        let base_account = create_base_account(&address);
        let simulated_gas_used = 100000u64;

        let mut mock_signer = MockMultisig::new();
        mock_signer
            .expect_sign()
            .once()
            .returning(|_, _, _, _| Ok(vec![0u8; 64]));

        let mut mock_client = cosmos::MockCosmosClient::new();
        let base_account_clone = base_account.clone();
        mock_client.expect_account().times(2).returning(move |_| {
            Ok(QueryAccountResponse {
                account: Some(Any::from_msg(&base_account_clone).unwrap()),
            })
        });
        mock_client
            .expect_balance()
            .once()
            .with(predicate::eq(QueryBalanceRequest {
                address: address.to_string(),
                denom: gas_price_denom.to_string(),
            }))
            .return_once(|_| {
                Ok(QueryBalanceResponse {
                    balance: Some(Coin {
                        denom: gas_price_denom.to_string(),
                        amount: "1000000".to_string(),
                    }),
                })
            });
        mock_client.expect_simulate().once().return_once(move |_| {
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
            .return_once(move |_| {
                Err(report!(cosmos::Error::GrpcRequest(
                    tonic::Status::internal("broadcast failed")
                )))
            });

        let broadcaster = broadcaster::Broadcaster::builder()
            .client(mock_client)
            .chain_id(chain_id)
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();
        let msg_queue = empty();
        let mut broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .build();

        let messages = vec![dummy_msg()].try_into().unwrap();
        let result = broadcaster_task.broadcast(messages).await;
        assert!(result.is_err());
        assert_err_contains!(result, Error, Error::BroadcastTx);
    }
}
