use cosmrs::tx::MessageExt;
use cosmrs::Any;
use error_stack::report;
use k256::sha2::{Digest, Sha256};
use report::LoggableError;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tracing::{error, info};
use typed_builder::TypedBuilder;
use valuable::Valuable;

use crate::broadcaster::dec_coin::DecCoin;
use crate::cosmos;
use crate::tofnd::grpc::Multisig;
use crate::tofnd::{self};

mod broadcaster;
mod msg_queue;
mod proto;

type Result<T> = error_stack::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to enqueue message")]
    EnqueueMsg(#[from] mpsc::error::SendError<msg_queue::QueueMsg>),
    #[error("failed to estimate gas")]
    EstimateGas,
    #[error("failed to query account")]
    QueryAccount,
    #[error("invalid public key")]
    InvalidPubKey,
    #[error("failed to sign tx")]
    TxSigning,
    #[error("failed to broadcast tx")]
    BroadcastTx,
}

#[derive(TypedBuilder)]
pub struct BroadcasterTask<T, Q, S>
where
    T: cosmos::CosmosClient,
    Q: futures::Stream<Item = Vec<msg_queue::QueueMsg>> + Unpin,
    S: Multisig,
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
    Q: futures::Stream<Item = Vec<msg_queue::QueueMsg>> + Unpin,
    S: Multisig,
{
    pub async fn run(mut self) -> Result<()> {
        while let Some(msgs) = self.msg_queue.next().await {
            if msgs.is_empty() {
                continue;
            }

            let tx_res = self
                .broadcast(msgs.iter().map(|msg| msg.msg.clone()))
                .await
                .inspect(|res| {
                    info!(
                        tx_hash = res.txhash,
                        msg_count = msgs.len(),
                        "successfully broadcasted tx"
                    );
                })
                .inspect_err(|err| {
                    error!(
                        err = LoggableError::from(err).as_value(),
                        "failed to broadcast tx",
                    );
                });
            self.handle_tx_res(tx_res, msgs).await?;
        }

        Ok(())
    }

    async fn broadcast(
        &mut self,
        msgs: impl IntoIterator<Item = Any>,
    ) -> Result<cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse> {
        let batch_req = proto::axelar::auxiliary::v1beta1::BatchRequest {
            sender: self.broadcaster.address.as_ref().to_bytes(),
            messages: msgs.into_iter().collect(),
        }
        .to_any()
        .expect("failed to serialize proto message for batch request");
        let pub_key = self.broadcaster.pub_key;

        self.broadcaster
            .broadcast_cx()
            .await
            .broadcast(
                vec![batch_req],
                |sign_doc| {
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
                },
                self.gas_adjustment,
                self.gas_price.clone(),
            )
            .await
    }

    async fn handle_tx_res(
        &mut self,
        tx_res: Result<cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse>,
        msgs: Vec<msg_queue::QueueMsg>,
    ) -> Result<()> {
        let tx_hash = tx_res.map(|res| res.txhash);

        msgs.into_iter().enumerate().for_each(|(i, msg)| {
            match (msg.tx_res_callback, &tx_hash) {
                (None, _) => {}
                (Some(tx_res_callback), Ok(tx_hash)) => {
                    let _ = tx_res_callback.send(Ok((tx_hash.clone(), i as u64)));
                }
                (Some(tx_res_callback), Err(_)) => {
                    let _ = tx_res_callback.send(Err(report!(Error::BroadcastTx)));
                }
            };
        });

        if tx_hash.is_err() {
            self.broadcaster.reset().await
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::assert_err_contains;
    use cosmrs::proto::cosmos::auth::v1beta1::{BaseAccount, QueryAccountResponse};
    use cosmrs::proto::cosmos::base::abci::v1beta1::{GasInfo, TxResponse};
    use cosmrs::proto::cosmos::tx::v1beta1::{BroadcastTxResponse, Fee, SimulateResponse};
    use cosmrs::tx::MessageExt;
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
                    tx_res_callback: Some(tx),
                };

                (rx, msg)
            })
            .unzip();
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
                    account: Some(base_account.to_any().unwrap()),
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
            tx_res_callback: Some(tx),
        }];
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
                    account: Some(initial_account.to_any().unwrap()),
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
                    account: Some(reset_account.to_any().unwrap()),
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
    async fn broadcaster_task_should_handle_mixed_callbacks() {
        let pub_key = random_cosmos_public_key();
        let address = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let base_account = create_base_account(&address);

        let (tx, rx) = oneshot::channel();
        let queue_msgs = vec![
            QueueMsg {
                msg: dummy_msg(),
                gas: 50000,
                tx_res_callback: None,
            },
            QueueMsg {
                msg: dummy_msg(),
                gas: 50000,
                tx_res_callback: Some(tx),
            },
        ];
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
                    account: Some(base_account.to_any().unwrap()),
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

        let (tx_hash, idx) = rx.await.unwrap().unwrap();
        assert_eq!(tx_hash, "tx_hash_success");
        assert_eq!(idx, 1);
    }

    #[tokio::test]
    async fn broadcaster_task_should_handle_signing_errors() {
        let pub_key = random_cosmos_public_key();
        let address = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let base_account = create_base_account(&address);
        let reset_account = create_base_account(&address);

        let (tx, rx) = oneshot::channel();
        let queue_msgs = vec![QueueMsg {
            msg: dummy_msg(),
            gas: 50000,
            tx_res_callback: Some(tx),
        }];
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
                    account: Some(base_account.to_any().unwrap()),
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
            .expect_account()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(QueryAccountResponse {
                    account: Some(reset_account.to_any().unwrap()),
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
            tx_res_callback: Some(tx_1),
        }];
        let batch_2 = vec![QueueMsg {
            msg: dummy_msg(),
            gas: 50000,
            tx_res_callback: Some(tx_2),
        }];
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
                    account: Some(base_account.to_any().unwrap()),
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
            tx_res_callback: Some(tx_1),
        }];
        let batch_2 = vec![QueueMsg {
            msg: dummy_msg(),
            gas: 50000,
            tx_res_callback: Some(tx_2),
        }];
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
                    account: Some(initial_account.to_any().unwrap()),
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
                    account: Some(reset_account.to_any().unwrap()),
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
            tx_res_callback: Some(tx),
        }];
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
                    account: Some(base_account.to_any().unwrap()),
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
