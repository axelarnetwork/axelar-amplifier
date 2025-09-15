use std::future::Future;
use std::ops::Mul;
use std::sync::Arc;

use cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse;
use cosmrs::tx::Fee;
use cosmrs::{tendermint, Any, Coin, Denom, Gas};
use error_stack::{ensure, report, Context, ResultExt};
use num_traits::cast;
use regex::Regex;
use report::ResultCompatExt;
use tokio::sync::{RwLock, RwLockWriteGuard};
use typed_builder::TypedBuilder;

use super::{Error, Result};
use crate::broadcast::dec_coin::DecCoin;
use crate::broadcast::Tx;
use crate::types::{CosmosPublicKey, TMAddress};
use crate::{cosmos, PREFIX};

/// `Broadcaster` provides transaction broadcasting functionality for Cosmos networks.
///
/// This struct handles:
/// - Transaction creation and signing
/// - Sequence number management across concurrent broadcasts
/// - Gas estimation
/// - Error recovery
///
/// # Thread Safety
///
/// `Broadcaster` is designed to be thread-safe with internal sequence number synchronization,
/// allowing it to be safely cloned and used across multiple tasks concurrently.
///
/// # Sequence Management
///
/// The account sequence is automatically incremented after successful broadcasts and
/// reset to the on-chain value after failures, ensuring the next transaction always
/// uses the correct sequence number.
///
/// # Transaction Flow
///
/// 1. Retrieves account info on initialization
/// 2. Manages sequence number tracking internally
/// 3. Creates transactions with proper chain parameters
/// 4. Signs transactions using provided signing function
/// 5. Broadcasts transactions to the Cosmos network
/// 6. Handles sequence recovery on broadcast failures
///
/// # Example Usage
///
/// ```rust,ignore
/// let broadcaster = Broadcaster::builder()
///            .client(mock_client)
///            .chain_id(chain_id)
///            .pub_key(pub_key)
///            .gas_adjustment(gas_adjustment)
///            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
///            .build()
///            .await?;
/// let gas = broadcaster.estimate_gas(messages).await?;
/// let tx_response = broadcaster
///     .broadcast(messages, fee, sign_function)
///     .await?;
/// ```
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
    gas_adjustment: f64,
    gas_price: DecCoin,
}

// Required parameters for the builder
#[derive(TypedBuilder)]
#[builder(builder_type(vis = "pub", name = BroadcasterBuilder), build_method(vis = "", name = build_internal))]
struct BroadcasterBuilderParams<T>
where
    T: cosmos::CosmosClient,
{
    client: T,
    chain_id: tendermint::chain::Id,
    pub pub_key: CosmosPublicKey,
    gas_adjustment: f64,
    gas_price: DecCoin,
}

impl<T>
    BroadcasterBuilder<
        T,
        (
            (T,),
            (tendermint::chain::Id,),
            (CosmosPublicKey,),
            (f64,),
            (DecCoin,),
        ),
    >
where
    T: cosmos::CosmosClient,
{
    /// Builds a new `Broadcaster` instance.
    ///
    /// This method:
    /// 1. Derives the account address from the provided public key
    /// 2. Queries the account information from the blockchain
    /// 3. Initializes the broadcaster with the account's sequence number
    /// 4. Validates that the account has a balance
    ///
    /// # Returns
    ///
    /// A Result containing either the initialized `Broadcaster` or an error
    ///
    /// # Errors
    ///
    /// * `Error::InvalidPubKey` - If the public key cannot be converted to a valid Cosmos account address
    /// * `Error::AccountQuery` - If querying the account information from the blockchain fails
    /// * `Error::BalanceQuery` - If querying the account balance fails
    /// * `Error::InsufficientBalance` - If the account has no balance
    pub async fn build(self) -> Result<Broadcaster<T>> {
        let BroadcasterBuilderParams {
            mut client,
            chain_id,
            pub_key,
            gas_adjustment,
            gas_price,
        } = self.build_internal();

        let address = pub_key
            .account_id(PREFIX)
            .change_context(Error::InvalidPubKey)?
            .into();
        let account = cosmos::account(&mut client, &address)
            .await
            .change_context(Error::AccountQuery)?;

        let mut broadcaster = Broadcaster {
            client,
            chain_id,
            pub_key,
            address,
            acc_number: account.account_number,
            acc_sequence: Arc::new(RwLock::new(account.sequence)),
            gas_adjustment,
            gas_price,
        };

        let denom: Denom = broadcaster.gas_price.denom.clone().into();
        let address = broadcaster.address.clone();

        let balance = cosmos::balance(&mut broadcaster.client, &address, &denom)
            .await
            .change_context(Error::BalanceQuery)?;
        ensure!(
            balance.amount > 0,
            Error::InsufficientBalance { address, balance }
        );

        Ok(broadcaster)
    }
}

impl<T> Broadcaster<T>
where
    T: cosmos::CosmosClient,
{
    pub fn builder() -> BroadcasterBuilder<T> {
        BroadcasterBuilderParams::builder()
    }

    /// Estimates the gas required for a transaction containing the given messages.
    ///
    /// This performs a simulated execution of the transaction without actually
    /// broadcasting it, to determine gas costs.
    ///
    /// # Arguments
    ///
    /// * `msgs` - The Cosmos messages to include in the transaction
    ///
    /// # Returns
    ///
    /// A Result containing either the estimated gas amount or an error
    ///
    /// # Errors
    ///
    /// * `Error::EstimateGas` - If the gas estimation fails
    pub async fn estimate_gas(&mut self, msgs: Vec<Any>) -> Result<Gas> {
        let mut acc_sequence = self.acc_sequence.write().await;

        let res =
            match cosmos::estimate_gas(&mut self.client, msgs.clone(), self.pub_key, *acc_sequence)
                .await
            {
                Ok(gas) => Ok(gas),
                Err(e) => match parse_sequence_error(&e) {
                    // Retry with the expected sequence number
                    Some(expected_seq) => {
                        *acc_sequence = expected_seq;
                        cosmos::estimate_gas(&mut self.client, msgs, self.pub_key, *acc_sequence)
                            .await
                    }
                    // Return the error if not a sequence mismatch error
                    None => Err(e),
                },
            };

        res.change_context(Error::EstimateGas)
    }

    /// Broadcasts a transaction to the Cosmos blockchain.
    ///
    /// This method:
    /// 1. Creates a transaction with the provided messages and fee
    /// 2. Signs the transaction using the provided signing function
    /// 3. Broadcasts the signed transaction to the blockchain
    /// 4. Updates the account sequence number on success
    /// 5. Resets the sequence number on failure
    ///
    /// # Arguments
    ///
    /// * `msgs` - The Cosmos messages to include in the transaction
    /// * `fee` - The fee to pay for the transaction
    /// * `sign_fn` - A function that signs the transaction bytes
    ///
    /// # Returns
    ///
    /// A Result containing either the transaction response or an error
    ///
    /// # Errors
    ///
    /// * `Error::TxSigning` - If signing the transaction fails
    /// * `Error::BroadcastTx` - If broadcasting the transaction fails
    ///
    /// # Thread Safety
    ///
    /// This method acquires a write lock on the account sequence, ensuring that
    /// concurrent broadcasts use distinct sequence numbers.
    pub async fn broadcast<F, Fut, Err>(&mut self, msgs: Vec<Any>, sign_fn: F) -> Result<TxResponse>
    where
        F: Fn(Vec<u8>) -> Fut,
        Fut: Future<Output = error_stack::Result<Vec<u8>, Err>>,
        Err: Context,
    {
        let fee = self.estimate_fee(msgs.clone()).await?;
        let mut acc_sequence = self.acc_sequence.write().await;

        let tx = Tx::builder()
            .msgs(msgs)
            .pub_key(self.pub_key)
            .acc_sequence(*acc_sequence)
            .fee(fee)
            .build()
            .sign_with(&self.chain_id, self.acc_number, sign_fn)
            .await
            .change_context(Error::SignTx)?;

        match cosmos::broadcast(&mut self.client, tx).await {
            Ok(tx_response) => {
                // increment sequence number on successful broadcast
                *acc_sequence = acc_sequence
                    .checked_add(1)
                    .expect("account sequence must not overflow");

                Ok(tx_response)
            }
            Err(err) => {
                // reset sequence number on failed broadcast
                reset_sequence(&mut self.client, &self.address, acc_sequence).await?;

                Err(err).change_context(Error::BroadcastTx)
            }
        }
    }

    async fn estimate_fee(&mut self, msgs: Vec<Any>) -> Result<Fee> {
        let gas = self.estimate_gas(msgs).await? as f64 * self.gas_adjustment;

        let fee = Fee::from_amount_and_gas(
            Coin::new(
                cast(gas.mul(self.gas_price.amount).ceil()).ok_or(report!(Error::FeeAdjustment))?,
                self.gas_price.denom.as_ref(),
            )
            .change_context(Error::FeeAdjustment)?,
            cast::<f64, u64>(gas).ok_or(report!(Error::FeeAdjustment))?,
        );

        Ok(fee)
    }
}

async fn reset_sequence<T>(
    client: &mut T,
    address: &TMAddress,
    mut acc_sequence: RwLockWriteGuard<'_, u64>,
) -> Result<()>
where
    T: cosmos::CosmosClient,
{
    let account = cosmos::account(client, address)
        .await
        .change_context(Error::AccountQuery)?;
    *acc_sequence = account.sequence;

    Ok(())
}

fn parse_sequence_error(error: &impl std::fmt::Display) -> Option<u64> {
    let error_str = error.to_string();

    let re =
        Regex::new(r"account sequence mismatch, expected (\d+), got (\d+)").expect("Invalid regex");

    re.captures(&error_str)
        .and_then(|caps| caps.get(1))
        .and_then(|m| m.as_str().parse::<u64>().ok())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};

    use axelar_wasm_std::assert_err_contains;
    use cosmos_sdk_proto::cosmos::base::v1beta1::Coin;
    use cosmrs::proto::cosmos::auth::v1beta1::{BaseAccount, QueryAccountResponse};
    use cosmrs::proto::cosmos::bank::v1beta1::{QueryBalanceRequest, QueryBalanceResponse};
    use cosmrs::proto::cosmos::base::abci::v1beta1::{GasInfo, TxResponse};
    use cosmrs::proto::cosmos::tx::v1beta1::{BroadcastTxResponse, SimulateResponse};
    use cosmwasm_std::to_hex;
    use error_stack::Report;
    use k256::sha2::Sha256;
    use mockall::{predicate, Sequence};
    use prost::Message;
    use rand::rngs::OsRng;
    use sha3::Digest;

    use super::*;
    use crate::broadcast::{test_utils, Error};
    use crate::types::{random_cosmos_public_key, PublicKey};
    use crate::PREFIX;

    const DENOM: &str = "uaxl";

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

    fn setup_client(
        address: String,
        account_number: u64,
        sequence: u64,
    ) -> (cosmos::MockCosmosClient, Sequence) {
        let base_account = BaseAccount {
            address,
            pub_key: None,
            account_number,
            sequence,
        };

        let mut mock_client = cosmos::MockCosmosClient::new();
        let mut seq = Sequence::new();

        mock_client
            .expect_account()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(QueryAccountResponse {
                    account: Some(Any::from_msg(&base_account).unwrap()),
                })
            });

        (mock_client, seq)
    }

    fn setup_client_with_account_missing() -> (cosmos::MockCosmosClient, Sequence) {
        let mut mock_client = cosmos::MockCosmosClient::new();
        let mut seq = Sequence::new();

        mock_client
            .expect_account()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| Err(error_stack::report!(cosmos::Error::AccountMissing)));

        (mock_client, seq)
    }

    fn setup_client_with_balance(
        address: String,
        account_number: u64,
        sequence: u64,
        balance: String,
    ) -> (cosmos::MockCosmosClient, Sequence) {
        let (mut mock_client, mut seq) = setup_client(address.clone(), account_number, sequence);

        mock_client
            .expect_balance()
            .once()
            .in_sequence(&mut seq)
            .with(predicate::eq(QueryBalanceRequest {
                address,
                denom: DENOM.to_string(),
            }))
            .return_once(move |_| {
                Ok(QueryBalanceResponse {
                    balance: Some(Coin {
                        denom: DENOM.to_string(),
                        amount: balance,
                    }),
                })
            });

        (mock_client, seq)
    }

    fn setup_client_with_balance_error(
        address: String,
        account_number: u64,
        sequence: u64,
    ) -> (cosmos::MockCosmosClient, Sequence) {
        let (mut mock_client, mut seq) = setup_client(address.clone(), account_number, sequence);

        mock_client
            .expect_balance()
            .once()
            .in_sequence(&mut seq)
            .with(predicate::eq(QueryBalanceRequest {
                address,
                denom: DENOM.to_string(),
            }))
            .return_once(move |_| {
                Err(report!(cosmos::Error::GrpcRequest(
                    tonic::Status::internal("balance query failed")
                )))
            });

        (mock_client, seq)
    }

    async fn setup_broadcaster_with_gas_info(
        mock_client: cosmos::MockCosmosClient,
        pub_key: CosmosPublicKey,
        gas_adjustment: f64,
        gas_price_amount: f64,
    ) -> Result<Broadcaster<cosmos::MockCosmosClient>> {
        let chain_id: tendermint::chain::Id = "test-chain-id".parse().unwrap();

        Broadcaster::builder()
            .client(mock_client)
            .chain_id(chain_id)
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, DENOM).unwrap())
            .build()
            .await
    }

    async fn setup_broadcaster(
        mock_client: cosmos::MockCosmosClient,
        pub_key: CosmosPublicKey,
    ) -> Result<Broadcaster<cosmos::MockCosmosClient>> {
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;

        setup_broadcaster_with_gas_info(mock_client, pub_key, gas_adjustment, gas_price_amount)
            .await
    }

    fn setup_broadcast_expectations(
        mut mock_client: cosmos::MockCosmosClient,
        mock_seq: &mut Sequence,
        txhash: String,
        sequence: u64,
    ) -> cosmos::MockCosmosClient {
        let gas_used = 100000u64;

        mock_client
            .expect_simulate()
            .once()
            .in_sequence(mock_seq)
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
            .in_sequence(mock_seq)
            .withf(move |req| sequence == decode_sequence(&req.tx_bytes))
            .return_once(move |_| {
                Ok(BroadcastTxResponse {
                    tx_response: Some(TxResponse {
                        txhash,
                        ..Default::default()
                    }),
                })
            });

        mock_client
    }

    #[tokio::test]
    async fn broadcaster_build_should_succeed() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let account_number = 42u64;
        let sequence = 10u64;

        let (mock_client, _) = setup_client_with_balance(
            address.to_string(),
            account_number,
            sequence,
            "1000000".to_string(),
        );
        let result = setup_broadcaster(mock_client, pub_key).await;

        assert!(result.is_ok());
        let broadcaster = result.unwrap();
        assert_eq!(broadcaster.address, address);
        assert_eq!(broadcaster.acc_number, account_number);
        assert_eq!(*broadcaster.acc_sequence.read().await, sequence);
    }

    #[tokio::test]
    async fn broadcaster_build_should_fail_if_balance_query_fails() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let account_number = 42u64;
        let sequence = 10u64;

        let (mock_client, _) =
            setup_client_with_balance_error(address.to_string(), account_number, sequence);
        let result = setup_broadcaster(mock_client, pub_key).await;

        assert_err_contains!(result, Error, Error::BalanceQuery);
    }

    #[tokio::test]
    async fn broadcaster_build_should_fail_if_balance_is_zero() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let account_number = 42u64;
        let sequence = 10u64;

        let (mock_client, _) = setup_client_with_balance(
            address.to_string(),
            account_number,
            sequence,
            "0".to_string(),
        );
        let result = setup_broadcaster(mock_client, pub_key).await;

        assert_err_contains!(result, Error, Error::InsufficientBalance { .. });
    }

    #[tokio::test]
    async fn broadcaster_build_should_fail_with_invalid_public_key() {
        let invalid_pub_key: CosmosPublicKey = PublicKey::new_ed25519(
            ed25519_dalek::SigningKey::generate(&mut OsRng)
                .verifying_key()
                .to_bytes(),
        )
        .unwrap()
        .try_into()
        .unwrap();

        let mock_client = cosmos::MockCosmosClient::new();
        let result = setup_broadcaster(mock_client, invalid_pub_key).await;

        assert_err_contains!(result, Error, Error::InvalidPubKey);
    }

    #[tokio::test]
    async fn broadcaster_build_should_fail_with_query_account_error() {
        let pub_key = random_cosmos_public_key();

        let (mock_client, _) = setup_client_with_account_missing();
        let result = setup_broadcaster(mock_client, pub_key).await;

        assert_err_contains!(result, Error, Error::AccountQuery);
    }

    #[tokio::test]
    async fn estimate_gas_should_succeed() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let account_number = 42u64;
        let sequence = 10u64;
        let gas_used = 100000u64;

        let (mut mock_client, mut seq) = setup_client_with_balance(
            address.to_string(),
            account_number,
            sequence,
            "1000000".to_string(),
        );

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

        let mut broadcaster = setup_broadcaster(mock_client, pub_key).await.unwrap();

        let msgs = vec![dummy_msg()];
        let result = broadcaster.estimate_gas(msgs).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), gas_used);
        assert_eq!(*broadcaster.acc_sequence.read().await, sequence);
    }

    #[tokio::test]
    async fn broadcast_should_succeed() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let account_number = 42u64;
        let sequence = 10u64;
        let tx_hash = "ABC123";

        let (mock_client, mut seq) = setup_client_with_balance(
            address.to_string(),
            account_number,
            sequence,
            "1000000".to_string(),
        );

        let mock_client =
            setup_broadcast_expectations(mock_client, &mut seq, tx_hash.to_string(), sequence);

        let mut broadcaster = setup_broadcaster(mock_client, pub_key).await.unwrap();

        let msgs = vec![dummy_msg()];
        let sign_fn = |_: Vec<u8>| async { Ok::<Vec<u8>, Report<cosmos::Error>>(vec![0u8; 64]) };

        let result = broadcaster.broadcast(msgs, sign_fn).await;

        assert!(result.is_ok());
        let tx_response = result.unwrap();
        assert_eq!(tx_response.txhash, tx_hash);
        assert_eq!(*broadcaster.acc_sequence.read().await, sequence + 1);
    }

    #[tokio::test]
    async fn broadcast_should_apply_gas_adjustment_and_gas_price() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let account_number = 42u64;
        let sequence = 10u64;
        let gas_adjustment = 2.0;
        let gas_price_amount = 0.025;
        let simulated_gas_used = 100000u64;
        let expected_gas_limit = 200000u64; // 100000 * 2 = 200000
        let expected_fee_amount = 5000u64; // 200000 * 0.025 = 5000

        let tx_hash = "ABC123";

        let (mut mock_client, mut seq) = setup_client_with_balance(
            address.to_string(),
            account_number,
            sequence,
            "1000000".to_string(),
        );

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
                let actual_fee = test_utils::decode_gas_fee(&req.tx_bytes);
                assert_eq!(actual_fee.amount.len(), 1);

                actual_fee.gas_limit == expected_gas_limit
                    && actual_fee.amount.first().unwrap().amount == expected_fee_amount.to_string()
                    && actual_fee.amount.first().unwrap().denom == DENOM
            })
            .return_once(move |_| {
                Ok(BroadcastTxResponse {
                    tx_response: Some(TxResponse {
                        txhash: tx_hash.to_string(),
                        gas_wanted: expected_gas_limit as i64,
                        gas_used: 95000,
                        code: 0,
                        ..Default::default()
                    }),
                })
            });

        let mut broadcaster =
            setup_broadcaster_with_gas_info(mock_client, pub_key, gas_adjustment, gas_price_amount)
                .await
                .unwrap();

        let msgs = vec![dummy_msg()];
        let sign_fn = |_: Vec<u8>| async { Ok::<Vec<u8>, Report<cosmos::Error>>(vec![0u8; 64]) };

        let result = broadcaster.broadcast(msgs, sign_fn).await;

        assert!(result.is_ok());
        let tx_response = result.unwrap();
        assert_eq!(tx_response.txhash, tx_hash);
        assert_eq!(*broadcaster.acc_sequence.read().await, sequence + 1);
    }

    #[tokio::test]
    async fn estimate_gas_should_fail_with_gas_info_missing() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let account_number = 42u64;
        let sequence = 10u64;

        let (mut mock_client, _) = setup_client_with_balance(
            address.to_string(),
            account_number,
            sequence,
            "1000000".to_string(),
        );

        mock_client
            .expect_simulate()
            .return_once(move |_| Err(error_stack::report!(cosmos::Error::GasInfoMissing)));

        let mut broadcaster = setup_broadcaster(mock_client, pub_key).await.unwrap();

        let result = broadcaster.estimate_gas(vec![dummy_msg()]).await;

        assert_err_contains!(result, Error, Error::EstimateGas);
        assert_eq!(*broadcaster.acc_sequence.read().await, sequence);
    }

    #[tokio::test]
    async fn broadcast_should_fail_if_signing_fails() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let account_number = 42u64;
        let sequence = 10u64;
        let gas_used = 100000u64;

        let (mut mock_client, mut seq) = setup_client_with_balance(
            address.to_string(),
            account_number,
            sequence,
            "1000000".to_string(),
        );

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

        mock_client.expect_broadcast_tx().never();

        let mut broadcaster = setup_broadcaster(mock_client, pub_key).await.unwrap();

        let sign_fn = |_: Vec<u8>| async {
            Err::<Vec<u8>, Report<cosmos::Error>>(error_stack::report!(
                cosmos::Error::TxResponseMissing
            ))
        };

        let result = broadcaster.broadcast(vec![dummy_msg()], sign_fn).await;

        assert_err_contains!(result, Error, Error::SignTx);
        assert_eq!(*broadcaster.acc_sequence.read().await, sequence);
    }

    #[tokio::test]
    async fn broadcast_should_fail_with_broadcast_tx_error() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let account_number = 42u64;
        let sequence = 10u64;
        let gas_used = 100000u64;

        let (mut mock_client, mut seq) = setup_client_with_balance(
            address.to_string(),
            account_number,
            sequence,
            "1000000".to_string(),
        );
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
            .return_once(move |_| Err(error_stack::report!(cosmos::Error::TxResponseMissing)));
        let base_account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number,
            sequence,
        };
        mock_client
            .expect_account()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(QueryAccountResponse {
                    account: Some(Any::from_msg(&base_account).unwrap()),
                })
            });

        let mut broadcaster = setup_broadcaster(mock_client, pub_key).await.unwrap();

        let sign_fn = |_: Vec<u8>| async { Ok::<Vec<u8>, Report<cosmos::Error>>(vec![0u8; 64]) };

        let result = broadcaster.broadcast(vec![dummy_msg()], sign_fn).await;

        assert_err_contains!(result, Error, Error::BroadcastTx);
        assert_eq!(*broadcaster.acc_sequence.read().await, sequence);
    }

    #[tokio::test]
    async fn sequential_broadcasts_should_use_increasing_sequence_numbers() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let account_number = 42u64;
        let initial_sequence = 10u64;

        let (mock_client, mut seq) = setup_client_with_balance(
            address.to_string(),
            account_number,
            initial_sequence,
            "1000000".to_string(),
        );

        let mock_client = setup_broadcast_expectations(
            mock_client,
            &mut seq,
            "tx1".to_string(),
            initial_sequence,
        );

        let mock_client = setup_broadcast_expectations(
            mock_client,
            &mut seq,
            "tx2".to_string(),
            initial_sequence + 1,
        );

        let mut broadcaster = setup_broadcaster(mock_client, pub_key).await.unwrap();

        let sign_fn = |_: Vec<u8>| async { Ok::<Vec<u8>, Report<cosmos::Error>>(vec![0u8; 64]) };

        let result = broadcaster.broadcast(vec![dummy_msg()], sign_fn).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().txhash, "tx1");
        assert_eq!(*broadcaster.acc_sequence.read().await, initial_sequence + 1);

        let result = broadcaster.broadcast(vec![dummy_msg()], sign_fn).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().txhash, "tx2");
        assert_eq!(*broadcaster.acc_sequence.read().await, initial_sequence + 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sequence_management_should_be_thread_safe() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let account_number = 42u64;
        let initial_sequence = 10u64;
        let sequence = Arc::new(RwLock::new(initial_sequence));
        let gas_used = 100000u64;

        let (mut mock_client, _) = setup_client_with_balance(
            address.to_string(),
            account_number,
            *sequence.read().unwrap(),
            "1000000".to_string(),
        );

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

        let broadcaster = setup_broadcaster(mock_client, pub_key).await.unwrap();

        let gas_estimate_count = 30u64;
        let broadcast_count = 50u64;

        let gas_estimate_handles: Vec<_> = (0..gas_estimate_count)
            .map(|_| {
                let mut broadcaster_clone = broadcaster.clone();

                tokio::spawn(async move {
                    let _gas = broadcaster_clone
                        .estimate_gas(vec![dummy_msg()])
                        .await
                        .unwrap();
                })
            })
            .collect();
        let broadcast_handles: Vec<_> = (0..broadcast_count)
            .map(|_| {
                let mut broadcaster_clone = broadcaster.clone();

                tokio::spawn(async move {
                    let _tx = broadcaster_clone
                        .broadcast(vec![dummy_msg(), dummy_msg()], |_| async {
                            Ok::<Vec<u8>, Report<cosmos::Error>>(vec![0u8; 64])
                        })
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
