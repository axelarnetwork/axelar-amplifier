use std::future::Future;
use std::sync::Arc;

use cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse;
use cosmrs::{tendermint, Any, Gas};
use error_stack::{Context, ResultExt};
use report::ResultCompatExt;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::{Error, Result};
use crate::broadcaster::dec_coin::DecCoin;
use crate::broadcaster::tx::Tx;
use crate::types::{CosmosPublicKey, TMAddress};
use crate::{cosmos, PREFIX};

/// Simulation context for gas estimation
///
/// Holds a read lock on the sequence number, allowing multiple simulations
/// to occur concurrently. This is useful for estimating gas without actually
/// submitting transactions.
pub struct SimCx<'a, T> {
    client: &'a mut T,
    pub_key: CosmosPublicKey,
    acc_sequence: RwLockReadGuard<'a, u64>,
}

impl<'a, T> SimCx<'a, T>
where
    T: cosmos::CosmosClient,
{
    pub async fn estimate_gas(self, msgs: Vec<Any>) -> Result<Gas> {
        cosmos::estimate_gas(self.client, msgs, self.pub_key, *self.acc_sequence)
            .await
            .change_context(Error::EstimateGas)
    }
}

/// Broadcasting context for transaction submission
///
/// Holds a write lock on the sequence number, ensuring that only one broadcast
/// can happen at a time. This is necessary because each transaction must have
/// a unique sequence number, and we need to increment the sequence number
/// after a successful broadcast.
pub struct BroadcastCx<'a, T> {
    client: &'a mut T,
    chain_id: &'a tendermint::chain::Id,
    pub_key: CosmosPublicKey,
    acc_number: u64,
    acc_sequence: RwLockWriteGuard<'a, u64>,
}

impl<'a, T> BroadcastCx<'a, T>
where
    T: cosmos::CosmosClient,
{
    pub async fn broadcast<F, Fut, Err>(
        mut self,
        msgs: Vec<Any>,
        sign_fn: F,
        gas_adjustment: f64,
        gas_price: DecCoin,
    ) -> Result<TxResponse>
    where
        F: Fn(Vec<u8>) -> Fut,
        Fut: Future<Output = error_stack::Result<Vec<u8>, Err>>,
        Err: Context,
    {
        let fee = cosmos::estimate_fee(
            self.client,
            msgs.clone(),
            self.pub_key,
            *self.acc_sequence,
            gas_adjustment,
            gas_price,
        )
        .await
        .change_context(Error::EstimateGas)?;

        let tx = Tx::builder()
            .msgs(msgs)
            .pub_key(self.pub_key)
            .acc_sequence(*self.acc_sequence)
            .fee(fee)
            .build()
            .sign_with(self.chain_id, self.acc_number, sign_fn)
            .await
            .change_context(Error::TxSigning)?;

        cosmos::broadcast(self.client, tx)
            .await
            .change_context(Error::BroadcastTx)
            .inspect(|_| {
                *self.acc_sequence = self
                    .acc_sequence
                    .checked_add(1)
                    .expect("account sequence must not overflow");
            })
    }
}

/// A thread-safe transaction broadcaster for Cosmos chains
///
/// This struct manages sequence numbers for Cosmos transactions, ensuring that
/// they are properly incremented even when broadcasting from multiple threads.
/// It provides two contexts for transaction operations:
///
/// - `SimCx` - A simulation context that holds a read lock on the sequence number
/// - `BroadcastCx` - A broadcast context that holds a write lock on the sequence number
///
/// The sequence number is only incremented after a successful broadcast, ensuring
/// that failed transactions don't cause gaps in the sequence numbering.
///
/// Thread-safety is provided by using tokio's RwLock to protect the sequence number,
/// allowing multiple concurrent simulations (reads) but exclusive broadcasts (writes).
#[derive(Clone, Debug)]
pub struct Broadcaster<T>
where
    T: cosmos::CosmosClient,
{
    client: T,
    chain_id: tendermint::chain::Id,
    pub pub_key: CosmosPublicKey,
    pub address: TMAddress,
    acc_number: u64,
    acc_sequence: Arc<RwLock<u64>>,
}

impl<T> Broadcaster<T>
where
    T: cosmos::CosmosClient,
{
    pub async fn new(
        mut client: T,
        chain_id: tendermint::chain::Id,
        pub_key: CosmosPublicKey,
    ) -> Result<Self> {
        let address = pub_key
            .account_id(PREFIX)
            .change_context(Error::InvalidPubKey)?
            .into();
        let account = cosmos::account(&mut client, &address)
            .await
            .change_context(Error::QueryAccount)?;

        Ok(Self {
            client,
            chain_id,
            pub_key,
            address,
            acc_number: account.account_number,
            acc_sequence: Arc::new(RwLock::new(account.sequence)),
        })
    }

    pub async fn sim_cx(&mut self) -> SimCx<T> {
        SimCx {
            client: &mut self.client,
            pub_key: self.pub_key,
            acc_sequence: self.acc_sequence.read().await,
        }
    }

    pub async fn broadcast_cx(&mut self) -> BroadcastCx<T> {
        BroadcastCx {
            client: &mut self.client,
            chain_id: &self.chain_id,
            pub_key: self.pub_key,
            acc_number: self.acc_number,
            acc_sequence: self.acc_sequence.write().await,
        }
    }

    pub async fn reset(&mut self) -> Result<()> {
        let account = cosmos::account(&mut self.client, &self.address)
            .await
            .change_context(Error::QueryAccount)?;

        let mut sequence_guard = self.acc_sequence.write().await;
        *sequence_guard = account.sequence;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};

    use axelar_wasm_std::assert_err_contains;
    use cosmrs::proto::cosmos::auth::v1beta1::{BaseAccount, QueryAccountResponse};
    use cosmrs::proto::cosmos::base::abci::v1beta1::{GasInfo, TxResponse};
    use cosmrs::proto::cosmos::tx::v1beta1::{BroadcastTxResponse, SimulateResponse};
    use cosmrs::tx::MessageExt;
    use cosmwasm_std::to_hex;
    use error_stack::Report;
    use k256::sha2::Sha256;
    use mockall::Sequence;
    use prost::Message;
    use rand::rngs::OsRng;
    use sha3::Digest;

    use super::*;
    use crate::broadcaster::dec_coin::DecCoin;
    use crate::broadcaster_v2::Error;
    use crate::types::{random_cosmos_public_key, PublicKey};
    use crate::PREFIX;

    fn dummy_msg() -> Any {
        Any {
            type_url: "/cosmos.bank.v1beta1.MsgSend".to_string(),
            value: vec![1, 2, 3],
        }
    }

    fn decode_sequence<R>(req: &R) -> u64
    where
        R: AsRef<[u8]> + ?Sized,
    {
        let tx_raw = cosmrs::proto::cosmos::tx::v1beta1::TxRaw::decode(req.as_ref()).unwrap();
        let auth_info =
            cosmrs::proto::cosmos::tx::v1beta1::AuthInfo::decode(tx_raw.auth_info_bytes.as_slice())
                .unwrap();
        auth_info.signer_infos.first().unwrap().sequence
    }

    #[tokio::test]
    async fn broadcaster_new_should_succeed() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let account_number = 42u64;
        let sequence = 10u64;

        let base_account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number,
            sequence,
        };
        let base_account_any = base_account.to_any().unwrap();

        let mut mock_client = cosmos::MockCosmosClient::new();
        mock_client.expect_account().return_once(move |_| {
            Ok(QueryAccountResponse {
                account: Some(base_account_any),
            })
        });

        let result = Broadcaster::new(mock_client, chain_id, pub_key).await;

        assert!(result.is_ok());
        let broadcaster = result.unwrap();
        assert_eq!(broadcaster.address, address);
        assert_eq!(broadcaster.acc_number, account_number);
        assert_eq!(*broadcaster.acc_sequence.read().await, sequence);
    }

    #[tokio::test]
    async fn broadcaster_new_should_fail_with_invalid_public_key() {
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let invalid_pub_key = PublicKey::new_ed25519(
            ed25519_dalek::SigningKey::generate(&mut OsRng)
                .verifying_key()
                .to_bytes(),
        )
        .unwrap()
        .try_into()
        .unwrap();

        let mock_client = cosmos::MockCosmosClient::new();

        let result = Broadcaster::new(mock_client, chain_id, invalid_pub_key).await;
        assert_err_contains!(result, Error, Error::InvalidPubKey);
    }

    #[tokio::test]
    async fn broadcaster_new_should_fail_with_query_account_error() {
        let pub_key = random_cosmos_public_key();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();

        let mut mock_client = cosmos::MockCosmosClient::new();
        mock_client
            .expect_account()
            .return_once(move |_| Err(error_stack::report!(cosmos::Error::AccountMissing)));

        let result = Broadcaster::new(mock_client, chain_id, pub_key).await;

        assert_err_contains!(result, Error, Error::QueryAccount);
    }

    #[tokio::test]
    async fn context_creation_should_work_correctly() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let account_number = 42u64;
        let sequence = 10u64;

        let base_account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number,
            sequence,
        };
        let base_account_any = base_account.to_any().unwrap();

        let mut mock_client = cosmos::MockCosmosClient::new();
        mock_client.expect_account().return_once(move |_| {
            Ok(QueryAccountResponse {
                account: Some(base_account_any),
            })
        });

        let mut broadcaster = Broadcaster::new(mock_client, chain_id.clone(), pub_key)
            .await
            .unwrap();

        let sim_cx = broadcaster.sim_cx().await;
        assert_eq!(*sim_cx.acc_sequence, sequence);
        assert_eq!(sim_cx.pub_key, pub_key);

        drop(sim_cx);
        assert_eq!(*broadcaster.acc_sequence.read().await, sequence);

        let broadcast_cx = broadcaster.broadcast_cx().await;
        assert_eq!(*broadcast_cx.acc_sequence, sequence);
        assert_eq!(broadcast_cx.acc_number, account_number);
        assert_eq!(broadcast_cx.pub_key, pub_key);
        assert_eq!(broadcast_cx.chain_id, &chain_id);

        drop(broadcast_cx);
        assert_eq!(*broadcaster.acc_sequence.read().await, sequence);
    }

    #[tokio::test]
    async fn reset_should_update_sequence_with_latest_account_data() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let account_number = 42u64;
        let initial_sequence = 10u64;
        let updated_sequence = 15u64;

        let initial_account = BaseAccount {
            address: address.to_string().clone(),
            pub_key: None,
            account_number,
            sequence: initial_sequence,
        };
        let initial_account_any = initial_account.to_any().unwrap();

        let updated_account = BaseAccount {
            address: address.to_string().clone(),
            pub_key: None,
            account_number,
            sequence: updated_sequence,
        };
        let updated_account_any = updated_account.to_any().unwrap();

        let mut mock_client = cosmos::MockCosmosClient::new();
        mock_client.expect_account().return_once(move |_| {
            Ok(QueryAccountResponse {
                account: Some(initial_account_any),
            })
        });

        let mut mock_client_for_reset = cosmos::MockCosmosClient::new();
        mock_client_for_reset
            .expect_account()
            .return_once(move |_| {
                Ok(QueryAccountResponse {
                    account: Some(updated_account_any),
                })
            });

        let mut broadcaster = Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();

        assert_eq!(*broadcaster.acc_sequence.read().await, initial_sequence);

        broadcaster.client = mock_client_for_reset;

        broadcaster.reset().await.unwrap();
        assert_eq!(*broadcaster.acc_sequence.read().await, updated_sequence);
    }

    #[tokio::test]
    async fn sim_cx_estimate_gas_should_succeed() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let account_number = 42u64;
        let sequence = 10u64;

        let gas_used = 100000u64;

        let base_account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number,
            sequence,
        };
        let base_account_any = base_account.to_any().unwrap();

        let mut mock_client = cosmos::MockCosmosClient::new();
        mock_client.expect_account().return_once(move |_| {
            Ok(QueryAccountResponse {
                account: Some(base_account_any),
            })
        });

        mock_client.expect_simulate().return_once(move |_| {
            Ok(SimulateResponse {
                gas_info: Some(GasInfo {
                    gas_wanted: 0,
                    gas_used,
                }),
                result: None,
            })
        });

        let mut broadcaster = Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();

        let msgs = vec![dummy_msg()];
        let sim_cx = broadcaster.sim_cx().await;
        let result = sim_cx.estimate_gas(msgs).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), gas_used);
        assert_eq!(*broadcaster.acc_sequence.read().await, sequence);
    }

    #[tokio::test]
    async fn broadcast_cx_broadcast_should_succeed() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let account_number = 42u64;
        let sequence = 10u64;
        let gas_adjustment = 1.5;

        let amount = 0.025;
        let denom_str = "uaxl";
        let gas_price = DecCoin::new(amount, denom_str).unwrap();

        let gas_used = 100000u64;
        let tx_hash = "ABC123";

        let base_account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number,
            sequence,
        };
        let base_account_any = base_account.to_any().unwrap();

        let mut seq = Sequence::new();
        let mut mock_client = cosmos::MockCosmosClient::new();
        mock_client
            .expect_account()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(QueryAccountResponse {
                    account: Some(base_account_any),
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
                        gas_used,
                    }),
                    result: None,
                })
            });

        mock_client
            .expect_broadcast_tx()
            .once()
            .in_sequence(&mut seq)
            .withf(move |req| sequence == decode_sequence(&req.tx_bytes))
            .return_once(move |_| {
                Ok(BroadcastTxResponse {
                    tx_response: Some(TxResponse {
                        txhash: tx_hash.to_string(),
                        ..Default::default()
                    }),
                })
            });

        let mut broadcaster = Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();

        let msgs = vec![dummy_msg()];
        let sign_fn = |_: Vec<u8>| async { Ok::<Vec<u8>, Report<cosmos::Error>>(vec![0u8; 64]) };

        let broadcast_cx = broadcaster.broadcast_cx().await;
        let result = broadcast_cx
            .broadcast(msgs, sign_fn, gas_adjustment, gas_price)
            .await;

        assert!(result.is_ok());
        let tx_response = result.unwrap();
        assert_eq!(tx_response.txhash, tx_hash);
        assert_eq!(*broadcaster.acc_sequence.read().await, sequence + 1);
    }

    #[tokio::test]
    async fn sim_cx_estimate_gas_should_fail_with_gas_info_missing() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let account_number = 42u64;
        let sequence = 10u64;

        let base_account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number,
            sequence,
        };
        let base_account_any = base_account.to_any().unwrap();

        let mut mock_client = cosmos::MockCosmosClient::new();
        mock_client.expect_account().return_once(move |_| {
            Ok(QueryAccountResponse {
                account: Some(base_account_any),
            })
        });

        mock_client
            .expect_simulate()
            .return_once(move |_| Err(error_stack::report!(cosmos::Error::GasInfoMissing)));

        let mut broadcaster = Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();

        let sim_cx = broadcaster.sim_cx().await;
        let result = sim_cx.estimate_gas(vec![dummy_msg()]).await;

        assert_err_contains!(result, Error, Error::EstimateGas);
        assert_eq!(*broadcaster.acc_sequence.read().await, sequence);
    }

    #[tokio::test]
    async fn broadcast_cx_should_fail_with_estimate_gas_error() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let account_number = 42u64;
        let sequence = 10u64;
        let gas_adjustment = 1.5;

        let amount = 0.025;
        let denom_str = "uaxl";
        let gas_price = DecCoin::new(amount, denom_str).unwrap();

        let base_account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number,
            sequence,
        };
        let base_account_any = base_account.to_any().unwrap();

        let mut mock_client = cosmos::MockCosmosClient::new();
        mock_client.expect_account().return_once(move |_| {
            Ok(QueryAccountResponse {
                account: Some(base_account_any),
            })
        });

        mock_client
            .expect_simulate()
            .return_once(move |_| Err(error_stack::report!(cosmos::Error::GasInfoMissing)));

        let mut broadcaster = Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();

        let sign_fn = |_: Vec<u8>| async { Ok::<Vec<u8>, Report<cosmos::Error>>(vec![0u8; 64]) };

        let broadcast_cx = broadcaster.broadcast_cx().await;
        let result = broadcast_cx
            .broadcast(vec![dummy_msg()], sign_fn, gas_adjustment, gas_price)
            .await;

        assert_err_contains!(result, Error, Error::EstimateGas);
        assert_eq!(*broadcaster.acc_sequence.read().await, sequence);
    }

    #[tokio::test]
    async fn broadcast_cx_should_fail_with_broadcast_tx_error() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let account_number = 42u64;
        let sequence = 10u64;
        let gas_adjustment = 1.5;
        let gas_used = 100000u64;

        let amount = 0.025;
        let denom_str = "uaxl";
        let gas_price = DecCoin::new(amount, denom_str).unwrap();

        let base_account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number,
            sequence,
        };
        let base_account_any = base_account.to_any().unwrap();

        let mut mock_client = cosmos::MockCosmosClient::new();
        mock_client.expect_account().return_once(move |_| {
            Ok(QueryAccountResponse {
                account: Some(base_account_any),
            })
        });

        mock_client.expect_simulate().return_once(move |_| {
            Ok(SimulateResponse {
                gas_info: Some(GasInfo {
                    gas_wanted: 0,
                    gas_used,
                }),
                result: None,
            })
        });

        mock_client
            .expect_broadcast_tx()
            .return_once(move |_| Err(error_stack::report!(cosmos::Error::TxResponseMissing)));

        let mut broadcaster = Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();

        let sign_fn = |_: Vec<u8>| async { Ok::<Vec<u8>, Report<cosmos::Error>>(vec![0u8; 64]) };

        let broadcast_cx = broadcaster.broadcast_cx().await;
        let result = broadcast_cx
            .broadcast(vec![dummy_msg()], sign_fn, gas_adjustment, gas_price)
            .await;

        assert_err_contains!(result, Error, Error::BroadcastTx);
        assert_eq!(*broadcaster.acc_sequence.read().await, sequence);
    }

    #[tokio::test]
    async fn sequential_broadcasts_should_use_increasing_sequence_numbers() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let account_number = 42u64;
        let initial_sequence = 10u64;
        let gas_adjustment = 1.5;
        let gas_used = 100000u64;

        let amount = 0.025;
        let denom_str = "uaxl";
        let gas_price = DecCoin::new(amount, denom_str).unwrap();

        let base_account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number,
            sequence: initial_sequence,
        };
        let base_account_any = base_account.to_any().unwrap();

        let mut seq = Sequence::new();
        let mut mock_client = cosmos::MockCosmosClient::new();
        mock_client
            .expect_account()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(QueryAccountResponse {
                    account: Some(base_account_any),
                })
            });
        mock_client
            .expect_simulate()
            .once()
            .in_sequence(&mut seq)
            .withf(move |req| initial_sequence == decode_sequence(&req.tx_bytes))
            .return_once(move |_| {
                Ok(SimulateResponse {
                    gas_info: Some(GasInfo {
                        gas_wanted: 0,
                        gas_used,
                    }),
                    result: None,
                })
            });
        mock_client
            .expect_broadcast_tx()
            .once()
            .in_sequence(&mut seq)
            .withf(move |req| initial_sequence == decode_sequence(&req.tx_bytes))
            .return_once(move |_| {
                Ok(BroadcastTxResponse {
                    tx_response: Some(TxResponse {
                        txhash: "tx1".to_string(),
                        ..Default::default()
                    }),
                })
            });
        mock_client
            .expect_simulate()
            .once()
            .in_sequence(&mut seq)
            .withf(move |req| (initial_sequence + 1) == decode_sequence(&req.tx_bytes))
            .return_once(move |_| {
                Ok(SimulateResponse {
                    gas_info: Some(GasInfo {
                        gas_wanted: 0,
                        gas_used,
                    }),
                    result: None,
                })
            });
        mock_client
            .expect_broadcast_tx()
            .once()
            .in_sequence(&mut seq)
            .withf(move |req| (initial_sequence + 1) == decode_sequence(&req.tx_bytes))
            .return_once(move |_| {
                Ok(BroadcastTxResponse {
                    tx_response: Some(TxResponse {
                        txhash: "tx2".to_string(),
                        ..Default::default()
                    }),
                })
            });

        let mut broadcaster = Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();

        let sign_fn = |_: Vec<u8>| async { Ok::<Vec<u8>, Report<cosmos::Error>>(vec![0u8; 64]) };

        let broadcast_cx = broadcaster.broadcast_cx().await;
        let result1 = broadcast_cx
            .broadcast(
                vec![dummy_msg()],
                sign_fn,
                gas_adjustment,
                gas_price.clone(),
            )
            .await;
        assert!(result1.is_ok());
        assert_eq!(result1.unwrap().txhash, "tx1");
        assert_eq!(*broadcaster.acc_sequence.read().await, initial_sequence + 1);

        let broadcast_cx = broadcaster.broadcast_cx().await;
        let result2 = broadcast_cx
            .broadcast(vec![dummy_msg()], sign_fn, gas_adjustment, gas_price)
            .await;
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap().txhash, "tx2");
        assert_eq!(*broadcaster.acc_sequence.read().await, initial_sequence + 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sequence_management_should_be_thread_safe() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();
        let account_number = 42u64;
        let initial_sequence = 10u64;
        let sequence = Arc::new(RwLock::new(initial_sequence));
        let gas_adjustment = 1.5;
        let gas_used = 100000u64;

        let amount = 0.025;
        let denom_str = "uaxl";
        let gas_price = DecCoin::new(amount, denom_str).unwrap();

        let base_account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number,
            sequence: *sequence.read().unwrap(),
        };
        let base_account_any = base_account.to_any().unwrap();

        let mut mock_client = cosmos::MockCosmosClient::new();
        mock_client.expect_account().return_once(move |_| {
            Ok(QueryAccountResponse {
                account: Some(base_account_any),
            })
        });
        let sequence_clone = sequence.clone();
        mock_client.expect_simulate().returning(move |req| {
            assert_eq!(
                decode_sequence(&req.tx_bytes),
                *sequence_clone.read().unwrap()
            );

            Ok(SimulateResponse {
                gas_info: Some(GasInfo {
                    gas_wanted: 0,
                    gas_used,
                }),
                result: None,
            })
        });
        let sequence_clone = sequence.clone();
        mock_client.expect_broadcast_tx().returning(move |req| {
            let mut sequence = sequence_clone.write().unwrap();
            assert_eq!(decode_sequence(&req.tx_bytes), *sequence);

            let mut hasher = Sha256::new();
            hasher.update(req.tx_bytes);
            let tx_hash: [u8; 32] = hasher.finalize().to_vec().try_into().unwrap();

            Ok(BroadcastTxResponse {
                tx_response: Some(TxResponse {
                    txhash: to_hex(tx_hash),
                    ..Default::default()
                }),
            })
            .inspect(|_| {
                *sequence = sequence.checked_add(1).unwrap();
            })
        });
        mock_client.expect_clone().returning(move || {
            let mut mock_client = cosmos::MockCosmosClient::new();

            let sequence_clone = sequence.clone();
            mock_client.expect_simulate().returning(move |req| {
                assert_eq!(
                    decode_sequence(&req.tx_bytes),
                    *sequence_clone.read().unwrap()
                );

                Ok(SimulateResponse {
                    gas_info: Some(GasInfo {
                        gas_wanted: 0,
                        gas_used,
                    }),
                    result: None,
                })
            });
            let sequence_clone = sequence.clone();
            mock_client.expect_broadcast_tx().returning(move |req| {
                let mut sequence = sequence_clone.write().unwrap();
                assert_eq!(decode_sequence(&req.tx_bytes), *sequence);

                let mut hasher = Sha256::new();
                hasher.update(req.tx_bytes);
                let tx_hash: [u8; 32] = hasher.finalize().to_vec().try_into().unwrap();

                Ok(BroadcastTxResponse {
                    tx_response: Some(TxResponse {
                        txhash: to_hex(tx_hash),
                        ..Default::default()
                    }),
                })
                .inspect(|_| {
                    *sequence = sequence.checked_add(1).unwrap();
                })
            });

            mock_client
        });

        let broadcaster = Broadcaster::new(mock_client, chain_id, pub_key)
            .await
            .unwrap();

        let gas_estimate_count = 30u64;
        let broadcast_count = 50u64;

        let gas_estimate_handles: Vec<_> = (0..gas_estimate_count)
            .into_iter()
            .map(|_| {
                let mut broadcaster_clone = broadcaster.clone();

                tokio::spawn(async move {
                    let _gas = broadcaster_clone
                        .sim_cx()
                        .await
                        .estimate_gas(vec![dummy_msg()])
                        .await
                        .unwrap();
                })
            })
            .collect();
        let broadcast_handles: Vec<_> = (0..broadcast_count)
            .into_iter()
            .map(|_| {
                let mut broadcaster_clone = broadcaster.clone();
                let gas_price_clone = gas_price.clone();

                tokio::spawn(async move {
                    let _tx = broadcaster_clone
                        .broadcast_cx()
                        .await
                        .broadcast(
                            vec![dummy_msg(), dummy_msg()],
                            |_| async { Ok::<Vec<u8>, Report<cosmos::Error>>(vec![0u8; 64]) },
                            gas_adjustment,
                            gas_price_clone,
                        )
                        .await
                        .unwrap();
                })
            })
            .collect();

        for handle in gas_estimate_handles {
            assert!(handle.await.is_ok());
        }
        for handle in broadcast_handles {
            assert!(handle.await.is_ok());
        }

        assert_eq!(
            *broadcaster.acc_sequence.read().await,
            initial_sequence + broadcast_count
        );
    }
}
