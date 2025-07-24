use std::fmt::Debug;
use std::ops::Mul;
use std::sync::Arc;
use std::time::Instant;

use axelar_wasm_std::nonempty;
use cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse;
use cosmrs::tx::Fee;
use cosmrs::{Any, Coin, Denom, Gas};
use dec_coin::DecCoin;
use error_stack::{ensure, report, ResultExt};
use k256::sha2::{Digest, Sha256};
use num_traits::cast;
use report::ResultCompatExt;
use thiserror::Error;
use tokio::sync::oneshot;
use tokio_stream::StreamExt;
use tracing::{error, info, instrument};
use typed_builder::TypedBuilder;

use crate::monitoring::metrics::Msg as MetricsMsg;
use crate::types::TMAddress;
use crate::{cosmos, monitoring, tofnd};

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
#[builder(build_method(vis="", name=build_internal))]
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
    gas_adjustment: f64,
    gas_price: DecCoin,
    #[builder(default = None, setter(strip_option))]
    tx_confirmer_client: Option<confirmer::TxConfirmerClient>,
    monitoring_client: monitoring::Client,
}

#[allow(non_camel_case_types)]
impl<
        T,
        Q,
        S,
        __tx_confirmer_client: ::typed_builder::Optional<Option<confirmer::TxConfirmerClient>>,
    >
    BroadcasterTaskBuilder<
        T,
        Q,
        S,
        (
            (broadcaster::Broadcaster<T>,),
            (Q,),
            (S,),
            (String,),
            (f64,),
            (DecCoin,),
            __tx_confirmer_client,
            (monitoring::Client,),
        ),
    >
where
    T: cosmos::CosmosClient,
    Q: futures::Stream<Item = nonempty::Vec<msg_queue::QueueMsg>> + Unpin + Debug,
    S: tofnd::Multisig,
{
    /// Builds and then validates the broadcaster task configuration by ensuring the account
    /// has sufficient balance.
    ///
    /// This method checks that the account associated with the broadcaster's address has
    /// a positive balance in the currency specified by the gas price denomination. This
    /// validation ensures that the broadcaster has funds to pay for transaction fees before
    /// attempting to process any messages.
    ///
    /// # Returns
    /// A Result containing a BroadcasterTask if validation succeeds, or an error if:
    /// - The balance query fails (Error::BalanceQuery)
    /// - The account has insufficient balance (Error::InsufficientBalance)
    pub async fn build(self) -> Result<BroadcasterTask<T, Q, S>> {
        let mut task = self.build_internal();

        let denom: Denom = task.gas_price.denom.clone().into();
        let address = task.broadcaster.address.clone();

        let balance = cosmos::balance(&mut task.broadcaster.client, &address, &denom)
            .await
            .change_context(Error::BalanceQuery)?;
        ensure!(
            balance.amount > 0,
            Error::InsufficientBalance { address, balance }
        );

        Ok(task)
    }
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
            let transaction_start_time = Instant::now();
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

            self.monitoring_client
                .metrics()
                .record_metric(MetricsMsg::TransactionBroadcast {
                    success: tx_hash.is_ok(),
                    duration: transaction_start_time.elapsed(),
                });

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
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use axelar_wasm_std::{assert_err_contains, err_contains};
    use cosmos_sdk_proto::cosmos::base::v1beta1::Coin;
    use cosmrs::proto::cosmos::auth::v1beta1::{BaseAccount, QueryAccountResponse};
    use cosmrs::proto::cosmos::bank::v1beta1::{QueryBalanceRequest, QueryBalanceResponse};
    use cosmrs::proto::cosmos::base::abci::v1beta1::{GasInfo, TxResponse};
    use cosmrs::proto::cosmos::tx::v1beta1::{BroadcastTxResponse, Fee, SimulateResponse};
    use cosmrs::{tendermint, Any};
    use error_stack::report;
    use futures::StreamExt;
    use mockall::{predicate, Sequence};
    use prost::Message;
    use tokio::sync::{mpsc, oneshot};
    use tokio_stream::wrappers::ReceiverStream;
    use tokio_stream::{empty, iter};

    use crate::broadcaster_v2::dec_coin::DecCoin;
    use crate::broadcaster_v2::msg_queue::QueueMsg;
    use crate::broadcaster_v2::{broadcaster, BroadcasterTask, Error};
    use crate::monitoring::metrics::Msg;
    use crate::monitoring::test_utils::create_test_monitoring_client;
    use crate::tofnd::{self, MockMultisig};
    use crate::types::{random_cosmos_public_key, TMAddress};
    use crate::{cosmos, monitoring, PREFIX};

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
    async fn broadcaster_task_validate_should_fail_if_balance_query_fails() {
        let pub_key = random_cosmos_public_key();
        let address = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let base_account = create_base_account(&address);

        let msg_queue = empty();
        let mock_signer = MockMultisig::new();

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
                Err(report!(cosmos::Error::GrpcRequest(
                    tonic::Status::internal("balance query failed")
                )))
            });

        let broadcaster = broadcaster::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>)
            .expect("dummy monitoring server never fails ");
        let broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .gas_adjustment(1.5)
            .gas_price(DecCoin::new(0.025, "uaxl").unwrap())
            .monitoring_client(monitoring_client)
            .build();

        let result = broadcaster_task.await;
        assert!(result.is_err());
        assert_err_contains!(result, Error, Error::BalanceQuery);
    }

    #[tokio::test]
    async fn broadcaster_task_validate_should_fail_if_balance_is_zero() {
        let pub_key = random_cosmos_public_key();
        let address = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let base_account = create_base_account(&address);
        let zero_balance = "0";

        let msg_queue = empty();
        let mock_signer = MockMultisig::new();

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
            .return_once(move |_| {
                Ok(QueryBalanceResponse {
                    balance: Some(Coin {
                        denom: "uaxl".to_string(),
                        amount: zero_balance.to_string(),
                    }),
                })
            });

        let broadcaster = broadcaster::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>)
            .expect("dummy monitoring server never fails ");
        let broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .gas_adjustment(1.5)
            .gas_price(DecCoin::new(0.025, "uaxl").unwrap())
            .monitoring_client(monitoring_client)
            .build();

        let result = broadcaster_task.await;
        assert_err_contains!(result, Error, Error::InsufficientBalance { .. });
    }

    #[tokio::test]
    async fn broadcaster_task_should_process_message_queue_successfully_and_send_for_confirmation()
    {
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

        let broadcaster = broadcaster::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let (tx, rx) = mpsc::channel(1);
        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();
        let broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .gas_adjustment(1.5)
            .gas_price(DecCoin::new(0.025, "uaxl").unwrap())
            .tx_confirmer_client(tx)
            .monitoring_client(monitoring_client)
            .build()
            .await
            .unwrap();

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

        let broadcaster = broadcaster::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();
        let broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .gas_adjustment(1.5)
            .gas_price(DecCoin::new(0.025, "uaxl").unwrap())
            .monitoring_client(monitoring_client)
            .build()
            .await
            .unwrap();

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

        let broadcaster = broadcaster::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();
        let broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .gas_adjustment(1.5)
            .gas_price(DecCoin::new(0.025, "uaxl").unwrap())
            .monitoring_client(monitoring_client)
            .build()
            .await
            .unwrap();

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

        let broadcaster = broadcaster::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();
        let broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .gas_adjustment(1.5)
            .gas_price(DecCoin::new(0.025, "uaxl").unwrap())
            .monitoring_client(monitoring_client)
            .build()
            .await
            .unwrap();

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

        let broadcaster = broadcaster::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();
        let broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .gas_adjustment(1.5)
            .gas_price(DecCoin::new(0.025, "uaxl").unwrap())
            .monitoring_client(monitoring_client)
            .build()
            .await
            .unwrap();

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

        let broadcaster = broadcaster::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();
        let broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .gas_adjustment(1.5)
            .gas_price(DecCoin::new(0.025, "uaxl").unwrap())
            .monitoring_client(monitoring_client)
            .build()
            .await
            .unwrap();

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
        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();
        let broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, expected_denom).unwrap())
            .monitoring_client(monitoring_client)
            .build()
            .await
            .unwrap();

        let result = tokio::spawn(async move { broadcaster_task.run().await })
            .await
            .unwrap();
        assert!(result.is_ok());

        let (tx_hash, idx) = rx.await.unwrap().unwrap();
        assert_eq!(tx_hash, "tx_hash_success");
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

        let broadcaster = broadcaster::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let msg_queue = empty();
        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();
        let mut broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .monitoring_client(monitoring_client)
            .build()
            .await
            .unwrap();

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

        let broadcaster = broadcaster::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let msg_queue = empty();
        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();
        let mut broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .monitoring_client(monitoring_client)
            .build()
            .await
            .unwrap();

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

        let broadcaster = broadcaster::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let msg_queue = empty();
        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();
        let mut broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(MockMultisig::new())
            .key_id("test-key".to_string())
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .monitoring_client(monitoring_client)
            .build()
            .await
            .unwrap();

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

        let broadcaster = broadcaster::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let msg_queue = empty();
        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();
        let mut broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .monitoring_client(monitoring_client)
            .build()
            .await
            .unwrap();

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

        let broadcaster = broadcaster::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();
        let msg_queue = empty();
        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();
        let mut broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .monitoring_client(monitoring_client)
            .build()
            .await
            .unwrap();

        let messages = vec![dummy_msg()].try_into().unwrap();
        let result = broadcaster_task.broadcast(messages).await;
        assert!(result.is_err());
        assert_err_contains!(result, Error, Error::BroadcastTx);
    }

    #[tokio::test(start_paused = true)]
    async fn should_record_transaction_broadcast_metrics_successfully_for_success_and_failure() {
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

        let broadcaster = broadcaster::Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();

        let (monitoring_client, mut rx) = create_test_monitoring_client();

        let broadcaster_task = BroadcasterTask::builder()
            .broadcaster(broadcaster)
            .msg_queue(msg_queue)
            .signer(mock_signer)
            .key_id("test-key".to_string())
            .gas_adjustment(1.5)
            .gas_price(DecCoin::new(0.025, "uaxl").unwrap())
            .monitoring_client(monitoring_client)
            .build()
            .await
            .unwrap();

        let result = tokio::spawn(async move { broadcaster_task.run().await })
            .await
            .unwrap();
        assert!(result.is_ok());

        let result = rx_1.await.unwrap();
        assert!(result.is_err());

        let (tx_hash, idx) = rx_2.await.unwrap().unwrap();
        assert_eq!(tx_hash, "tx_hash_second_batch");
        assert_eq!(idx, 0);

        let msg1 = rx.recv().await.unwrap();

        match msg1 {
            Msg::TransactionBroadcast { success, duration } => {
                assert!(!success);
                assert!(duration > Duration::from_millis(0));
            }
            _ => panic!("expect TransactionBroadcast message"),
        }

        let msg2 = rx.recv().await.unwrap();

        match msg2 {
            Msg::TransactionBroadcast { success, duration } => {
                assert!(success);
                assert!(duration > Duration::from_millis(0));
            }
            _ => panic!("expect TransactionBroadcast message"),
        }

        assert!(rx.try_recv().is_err());
    }
}
