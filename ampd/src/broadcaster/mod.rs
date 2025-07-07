use std::cmp;
use std::convert::TryInto;
use std::ops::Mul;
use std::time::Duration;

use async_trait::async_trait;
use axelar_wasm_std::FnExt;
use cosmrs::proto::cosmos::auth::v1beta1::{BaseAccount, QueryAccountRequest};
use cosmrs::proto::cosmos::bank::v1beta1::QueryBalanceRequest;
use cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse;
use cosmrs::proto::cosmos::tx::v1beta1::{BroadcastMode, BroadcastTxRequest, SimulateRequest};
use cosmrs::proto::traits::MessageExt;
use cosmrs::tendermint::chain::Id;
use cosmrs::tx::Fee;
use cosmrs::{Amount, Any, Coin, Denom, Gas};
use dec_coin::DecCoin;
use error_stack::{ensure, report, FutureExt, Result, ResultExt};
use futures::TryFutureExt;
use itertools::Itertools;
use k256::sha2::{Digest, Sha256};
use mockall::automock;
use num_traits::{cast, Zero};
use report::ResultCompatExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;
use tx::Tx;
use typed_builder::TypedBuilder;

use crate::tofnd::Multisig;
use crate::types::{CosmosPublicKey, TMAddress};
use crate::{cosmos, tofnd};

pub mod confirm_tx;
// TODO: mods dec_coin and tx should moved to broadcaster_v2 and made private
// once this broadcaster mod is replaced
pub mod dec_coin;
pub mod tx;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed building tx")]
    TxBuilding,
    #[error("failed to estimate gas")]
    GasEstimation,
    #[error("failed to estimate fee")]
    FeeEstimation,
    #[error("broadcast failed")]
    Broadcast,
    #[error("failed to query balance for address '{address}' and denomination '{denom}'")]
    QueryBalance { address: TMAddress, denom: Denom },
    #[error("failed to query account for address '{address}'")]
    QueryAccount { address: TMAddress },
    #[error("address '{address}' controls no tokens of denomination '{denom}' that are required to pay broadcast fees")]
    NoTokensOfFeeDenom { address: TMAddress, denom: Denom },
    #[error("failed to encode broadcaster address from public key")]
    AddressEncoding,
    #[error("received response for query '{query}' could not be decoded")]
    MalformedResponse { query: String },
    #[error("address {address} is unknown, please make sure it is funded")]
    AccountNotFound { address: TMAddress },
    #[error("transaction not accepted by the node")]
    TxNotAccepted,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct Config {
    pub chain_id: Id,
    #[serde(with = "humantime_serde")]
    pub tx_fetch_interval: Duration,
    pub tx_fetch_max_retries: u32,
    pub gas_adjustment: f64,
    pub gas_price: DecCoin,
    pub batch_gas_limit: Gas,
    pub queue_cap: usize,
    #[serde(with = "humantime_serde")]
    pub broadcast_interval: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: "axelar-dojo-1".parse().unwrap(),
            tx_fetch_interval: Duration::from_millis(500),
            tx_fetch_max_retries: 10,
            gas_adjustment: 1.2,
            gas_price: DecCoin::new(0.00005, "uaxl").unwrap(),
            batch_gas_limit: 1000000,
            queue_cap: 1000,
            broadcast_interval: Duration::from_secs(5),
        }
    }
}

#[automock]
#[async_trait]
pub trait Broadcaster {
    fn sender_address(&self) -> TMAddress;
    async fn broadcast(&mut self, msgs: Vec<Any>) -> Result<TxResponse, Error>;
    async fn estimate_fee(&mut self, msgs: Vec<Any>) -> Result<Fee, Error>;
}

#[derive(TypedBuilder)]
pub struct UnvalidatedBasicBroadcaster<T, S>
where
    T: cosmos::CosmosClient + Send,
    S: Multisig + Send + Sync,
{
    client: T,
    signer: S,
    address_prefix: String,
    #[builder(default, setter(skip))]
    acc_sequence: Option<u64>,
    pub_key: (String, CosmosPublicKey),
    config: Config,
}

impl<T, S> UnvalidatedBasicBroadcaster<T, S>
where
    T: cosmos::CosmosClient + Send,
    S: Multisig + Send + Sync,
{
    pub async fn validate_fee_denomination(mut self) -> Result<BasicBroadcaster<T, S>, Error> {
        let denom: Denom = self.config.gas_price.denom.clone().into();
        let address: TMAddress = self.derive_address()?;

        ensure!(
            self.balance(address.clone(), denom.clone())
                .await?
                .then(extract_non_zero_amount)
                .is_some(),
            Error::NoTokensOfFeeDenom { denom, address }
        );

        Ok(BasicBroadcaster {
            client: self.client,
            signer: self.signer,
            address: address.clone(),
            acc_sequence: self.acc_sequence,
            pub_key: self.pub_key,
            config: self.config,
        })
    }

    fn derive_address(&self) -> Result<TMAddress, Error> {
        Ok(self
            .pub_key
            .1
            .account_id(&self.address_prefix)
            .change_context(Error::AddressEncoding)?
            .into())
    }

    async fn balance(&mut self, address: TMAddress, denom: Denom) -> Result<Coin, Error> {
        let coin = self
            .client
            .balance(QueryBalanceRequest {
                address: address.to_string(),
                denom: denom.to_string(),
            })
            .await
            .map(|response| response.balance)
            .map_err(|err| {
                err.change_context(Error::QueryBalance {
                    address: address.clone(),
                    denom: denom.clone(),
                })
            })?
            .ok_or(report!(Error::QueryBalance { address, denom }))?;

        ResultCompatExt::change_context(
            coin.try_into(),
            Error::MalformedResponse {
                query: "balance".to_string(),
            },
        )
    }
}

fn extract_non_zero_amount(coin: Coin) -> Option<Amount> {
    Some(coin.amount).filter(|amount| !amount.is_zero())
}

#[derive(Debug)]
pub struct BasicBroadcaster<T, S>
where
    T: cosmos::CosmosClient + Send,
    S: Multisig + Send + Sync,
{
    client: T,
    signer: S,
    address: TMAddress,
    acc_sequence: Option<u64>,
    pub_key: (String, CosmosPublicKey),
    config: Config,
}

#[async_trait]
impl<T, S> Broadcaster for BasicBroadcaster<T, S>
where
    T: cosmos::CosmosClient + Send,
    S: Multisig + Send + Sync,
{
    fn sender_address(&self) -> TMAddress {
        self.address.clone()
    }

    async fn broadcast(&mut self, msgs: Vec<Any>) -> Result<TxResponse, Error> {
        let (acc_number, acc_sequence) = self.acc_number_and_sequence().await?;
        let fee = self.estimate_fee(msgs.clone(), acc_sequence).await?;
        let tx = Tx::builder()
            .msgs(msgs)
            .fee(fee.clone())
            .pub_key(self.pub_key.1)
            .acc_sequence(acc_sequence)
            .build()
            .sign_with(&self.config.chain_id, acc_number, |sign_doc| {
                let mut hasher = Sha256::new();
                hasher.update(sign_doc);

                let sign_digest: [u8; 32] = hasher
                    .finalize()
                    .to_vec()
                    .try_into()
                    .expect("hash size must be 32");

                self.signer.sign(
                    self.pub_key.0.as_str(),
                    sign_digest,
                    (&self.pub_key.1).into(),
                    tofnd::Algorithm::Ecdsa,
                )
            })
            .await
            .change_context(Error::TxBuilding)?;

        let tx = BroadcastTxRequest {
            tx_bytes: tx.to_bytes().change_context(Error::TxBuilding)?,
            mode: BroadcastMode::Sync as i32,
        };

        let response = self
            .client
            .broadcast_tx(tx)
            .change_context(Error::Broadcast)
            .await?
            .tx_response
            .ok_or(report!(Error::Broadcast))?;

        info!(
            tx_hash = response.txhash,
            acc_number,
            acc_sequence = self.acc_sequence,
            fee.amount = fee.amount.iter().map(Coin::to_string).join(", "),
            ?fee.gas_limit,
            ?response,
            "transaction was broadcast"
        );

        ensure!(response.code == 0, Error::TxNotAccepted);

        self.acc_sequence.replace(
            acc_sequence
                .checked_add(1)
                .expect("account sequence must be less than u64::MAX"),
        );
        Ok(response)
    }

    async fn estimate_fee(&mut self, msgs: Vec<Any>) -> Result<Fee, Error> {
        let (_, acc_sequence) = self.acc_number_and_sequence().await?;

        self.estimate_fee(msgs, acc_sequence).await
    }
}

impl<T, S> BasicBroadcaster<T, S>
where
    T: cosmos::CosmosClient + Send,
    S: Multisig + Send + Sync,
{
    async fn acc_number_and_sequence(&mut self) -> Result<(u64, u64), Error> {
        let request = QueryAccountRequest {
            address: self.address.to_string(),
        };

        let response = self
            .client
            .account(request)
            .await
            .change_context(Error::QueryAccount {
                address: self.address.clone(),
            })?;

        let account = response.account.map_or(
            Err(report!(Error::AccountNotFound {
                address: self.address.clone()
            })),
            decode_base_account,
        )?;

        let acc_sequence = self.acc_sequence.insert(cmp::max(
            account.sequence,
            self.acc_sequence.unwrap_or_default(),
        ));

        Ok((account.account_number, *acc_sequence))
    }

    async fn estimate_fee(&mut self, msgs: Vec<Any>, acc_sequence: u64) -> Result<Fee, Error> {
        let sim_tx = Tx::builder()
            .msgs(msgs)
            .pub_key(self.pub_key.1)
            .acc_sequence(acc_sequence)
            .build()
            .with_dummy_sig()
            .await
            .change_context(Error::TxBuilding)?
            .to_bytes()
            .change_context(Error::TxBuilding)?;

        self.estimate_gas(sim_tx).await.map(|gas| {
            let gas_adj = gas as f64 * self.config.gas_adjustment;

            Ok(Fee::from_amount_and_gas(
                Coin {
                    amount: cast(gas_adj.mul(self.config.gas_price.amount).ceil())
                        .ok_or(Error::FeeEstimation)?,
                    denom: self.config.gas_price.denom.clone().into(),
                },
                cast::<f64, u64>(gas_adj).ok_or(Error::FeeEstimation)?,
            ))
        })?
    }

    async fn estimate_gas(&mut self, tx_bytes: Vec<u8>) -> Result<u64, Error> {
        #[allow(deprecated)]
        self.client
            .simulate(SimulateRequest { tx: None, tx_bytes })
            .change_context(Error::GasEstimation)
            .and_then(|response| async {
                response
                    .gas_info
                    .map(|info| info.gas_used)
                    .ok_or(Error::GasEstimation.into())
            })
            .await
    }
}

fn decode_base_account(account: Any) -> Result<BaseAccount, Error> {
    account
        .to_msg()
        .change_context(Error::MalformedResponse {
            query: "account".to_string(),
        })
        .attach_printable_lazy(|| format!("{{ value = {:?} }}", account.value))
}

#[cfg(test)]
mod tests {
    use cosmrs::bank::MsgSend;
    use cosmrs::proto::cosmos::auth::v1beta1::{BaseAccount, QueryAccountResponse};
    use cosmrs::proto::cosmos::bank::v1beta1::QueryBalanceResponse;
    use cosmrs::proto::cosmos::base::abci::v1beta1::{GasInfo, TxResponse};
    use cosmrs::proto::cosmos::tx::v1beta1::{
        BroadcastTxResponse, GetTxResponse, SimulateResponse,
    };
    use cosmrs::proto::Any;
    use cosmrs::tx::Msg;
    use cosmrs::{AccountId, Coin, Denom};
    use k256::ecdsa::SigningKey;
    use rand::rngs::OsRng;
    use report::ErrorExt;
    use tokio::test;
    use tonic::Status;

    use crate::broadcaster::cosmos::MockCosmosClient;
    use crate::broadcaster::{
        BasicBroadcaster, Broadcaster, Config, Error, UnvalidatedBasicBroadcaster,
    };
    use crate::tofnd::MockMultisig;
    use crate::types::{CosmosPublicKey, PublicKey, TMAddress};
    use crate::PREFIX;

    #[test]
    async fn broadcaster_has_incorrect_fee_denomination_return_error() {
        let key_id = "key_uid".to_string();
        let known_denom = "some/other/denom".parse().unwrap();
        let priv_key = k256::ecdsa::SigningKey::random(&mut OsRng);

        let signer = init_mock_signer(&key_id, &priv_key);
        let client = setup_balance_mock(MockCosmosClient::new(), &known_denom);
        let broadcaster = init_unvalidated_broadcaster(
            client,
            signer,
            key_id,
            PublicKey::new_secp256k1(priv_key.verifying_key().to_sec1_bytes()).unwrap(),
        );

        let report = broadcaster.validate_fee_denomination().await.unwrap_err();
        assert!(matches!(
            report.current_context(),
            Error::NoTokensOfFeeDenom { .. }
        ));
    }

    #[test]
    async fn broadcaster_has_correct_fee_denomination_return_validated_broadcaster() {
        let key_id = "key_uid".to_string();
        let known_denom: Denom = Config::default().gas_price.denom.clone().into();
        let priv_key = k256::ecdsa::SigningKey::random(&mut OsRng);

        let signer = init_mock_signer(&key_id, &priv_key);
        let client = setup_balance_mock(MockCosmosClient::new(), &known_denom);
        let broadcaster = init_unvalidated_broadcaster(
            client,
            signer,
            key_id,
            PublicKey::new_secp256k1(priv_key.verifying_key().to_sec1_bytes()).unwrap(),
        );

        let result = broadcaster.validate_fee_denomination().await;
        assert!(result.is_ok());
    }

    #[test]
    async fn gas_estimation_call_failed() {
        let key_id = "key_uid".to_string();
        let known_denom: Denom = Config::default().gas_price.denom.clone().into();
        let priv_key = k256::ecdsa::SigningKey::random(&mut OsRng);

        let signer = init_mock_signer(&key_id, &priv_key);
        let mut client = setup_account_mock(
            setup_balance_mock(MockCosmosClient::new(), &known_denom),
            &priv_key,
        );
        client
            .expect_simulate()
            .returning(|_| Err(Status::unavailable("unavailable service").into_report()));
        let mut broadcaster = init_validated_broadcaster(
            client,
            signer,
            key_id,
            PublicKey::new_secp256k1(priv_key.verifying_key().to_sec1_bytes()).unwrap(),
        )
        .await;
        let msgs = vec![dummy_msg()];

        assert!(matches!(
            broadcaster
                .broadcast(msgs)
                .await
                .unwrap_err()
                .current_context(),
            Error::GasEstimation
        ));
    }

    #[test]
    async fn gas_estimation_none_response() {
        let key_id = "key_uid".to_string();
        let known_denom: Denom = Config::default().gas_price.denom.clone().into();
        let priv_key = k256::ecdsa::SigningKey::random(&mut OsRng);

        let signer = init_mock_signer(&key_id, &priv_key);
        let mut client = setup_account_mock(
            setup_balance_mock(MockCosmosClient::new(), &known_denom),
            &priv_key,
        );
        client.expect_simulate().once().returning(|_| {
            Ok(SimulateResponse {
                gas_info: None,
                result: None,
            })
        });
        let mut broadcaster = init_validated_broadcaster(
            client,
            signer,
            key_id,
            PublicKey::new_secp256k1(priv_key.verifying_key().to_sec1_bytes()).unwrap(),
        )
        .await;
        let msgs = vec![dummy_msg()];

        assert!(matches!(
            broadcaster
                .broadcast(msgs)
                .await
                .unwrap_err()
                .current_context(),
            Error::GasEstimation
        ));
    }

    #[test]
    async fn broadcast_failed() {
        let key_id = "key_uid".to_string();
        let known_denom: Denom = Config::default().gas_price.denom.clone().into();
        let priv_key = k256::ecdsa::SigningKey::random(&mut OsRng);

        let signer = init_mock_signer(&key_id, &priv_key);
        let mut client = setup_account_mock(
            setup_balance_mock(MockCosmosClient::new(), &known_denom),
            &priv_key,
        );
        client.expect_simulate().returning(|_| {
            Ok(SimulateResponse {
                gas_info: Some(GasInfo {
                    gas_wanted: 0,
                    gas_used: 0,
                }),
                result: None,
            })
        });
        client
            .expect_broadcast_tx()
            .returning(|_| Err(Status::aborted("failed").into_report()));
        let mut broadcaster = init_validated_broadcaster(
            client,
            signer,
            key_id,
            PublicKey::new_secp256k1(priv_key.verifying_key().to_sec1_bytes()).unwrap(),
        )
        .await;
        let msgs = vec![dummy_msg()];

        assert!(matches!(
            broadcaster
                .broadcast(msgs)
                .await
                .unwrap_err()
                .current_context(),
            Error::Broadcast
        ));
    }

    #[test]
    async fn broadcast_confirmed() {
        let key_id = "key_uid".to_string();
        let known_denom: Denom = Config::default().gas_price.denom.clone().into();
        let priv_key = k256::ecdsa::SigningKey::random(&mut OsRng);

        let signer = init_mock_signer(&key_id, &priv_key);
        let client = setup_broadcast_mock(setup_account_mock(
            setup_balance_mock(MockCosmosClient::new(), &known_denom),
            &priv_key,
        ));
        let mut broadcaster = init_validated_broadcaster(
            client,
            signer,
            key_id,
            PublicKey::new_secp256k1(priv_key.verifying_key().to_sec1_bytes()).unwrap(),
        )
        .await;
        let msgs = vec![dummy_msg()];

        assert_eq!(broadcaster.acc_sequence, None);
        assert!(broadcaster.broadcast(msgs).await.is_ok());
        assert_eq!(broadcaster.acc_sequence, Some(1));
    }

    #[test]
    async fn broadcast_confirmed_in_mem_acc_sequence_mismatch_with_on_chain() {
        let key_id = "key_uid".to_string();
        let known_denom: Denom = Config::default().gas_price.denom.clone().into();
        let priv_key = k256::ecdsa::SigningKey::random(&mut OsRng);

        let signer = init_mock_signer(&key_id, &priv_key);
        let mut client =
            setup_broadcast_mock(setup_balance_mock(MockCosmosClient::new(), &known_denom));
        let mut call_count = 0;
        client.expect_account().returning(move |request| {
            let mut account = BaseAccount {
                address: request.address,
                pub_key: None,
                account_number: 7,
                sequence: 0,
            };

            call_count += 1;

            account.sequence = match call_count {
                1 => 0,
                2 => 10,
                _ => 0,
            };

            Ok(QueryAccountResponse {
                account: Some(Any::from_msg(&account).unwrap()),
            })
        });
        let mut broadcaster = init_validated_broadcaster(
            client,
            signer,
            key_id,
            PublicKey::new_secp256k1(priv_key.verifying_key().to_sec1_bytes()).unwrap(),
        )
        .await;

        assert_eq!(broadcaster.acc_sequence, None);
        assert!(broadcaster.broadcast(vec![dummy_msg()]).await.is_ok());
        assert_eq!(broadcaster.acc_sequence, Some(1));
        assert!(broadcaster.broadcast(vec![dummy_msg()]).await.is_ok());
        assert_eq!(broadcaster.acc_sequence, Some(11));
        assert!(broadcaster.broadcast(vec![dummy_msg()]).await.is_ok());
        assert_eq!(broadcaster.acc_sequence, Some(12));
    }

    #[test]
    async fn account_query_failed_return_error() {
        let key_id = "key_uid".to_string();
        let known_denom: Denom = Config::default().gas_price.denom.clone().into();
        let priv_key = k256::ecdsa::SigningKey::random(&mut OsRng);

        let signer = init_mock_signer(&key_id, &priv_key);
        let mut client =
            setup_broadcast_mock(setup_balance_mock(MockCosmosClient::new(), &known_denom));
        client
            .expect_account()
            .returning(|_| Err(Status::aborted("aborted").into_report()));
        let mut broadcaster = init_validated_broadcaster(
            client,
            signer,
            key_id,
            PublicKey::new_secp256k1(priv_key.verifying_key().to_sec1_bytes()).unwrap(),
        )
        .await;

        for report in [
            broadcaster.broadcast(vec![dummy_msg()]).await.unwrap_err(),
            Broadcaster::estimate_fee(&mut broadcaster, vec![dummy_msg()])
                .await
                .unwrap_err(),
        ] {
            assert!(matches!(
                report.current_context(),
                Error::QueryAccount { .. }
            ));
        }
    }

    #[test]
    async fn account_not_found_returns_error() {
        let key_id = "key_uid".to_string();
        let known_denom: Denom = Config::default().gas_price.denom.clone().into();
        let priv_key = k256::ecdsa::SigningKey::random(&mut OsRng);

        let signer = init_mock_signer(&key_id, &priv_key);
        let mut client =
            setup_broadcast_mock(setup_balance_mock(MockCosmosClient::new(), &known_denom));
        client
            .expect_account()
            .returning(|_| Ok(QueryAccountResponse { account: None }));
        let mut broadcaster = init_validated_broadcaster(
            client,
            signer,
            key_id,
            PublicKey::new_secp256k1(priv_key.verifying_key().to_sec1_bytes()).unwrap(),
        )
        .await;

        for report in [
            broadcaster.broadcast(vec![dummy_msg()]).await.unwrap_err(),
            Broadcaster::estimate_fee(&mut broadcaster, vec![dummy_msg()])
                .await
                .unwrap_err(),
        ] {
            assert!(matches!(
                report.current_context(),
                Error::AccountNotFound { .. }
            ));
        }
    }

    #[test]
    async fn malformed_account_query_response_return_error() {
        let key_id = "key_uid".to_string();
        let known_denom: Denom = Config::default().gas_price.denom.clone().into();
        let priv_key = k256::ecdsa::SigningKey::random(&mut OsRng);

        let signer = init_mock_signer(&key_id, &priv_key);
        let mut client =
            setup_broadcast_mock(setup_balance_mock(MockCosmosClient::new(), &known_denom));
        client.expect_account().returning(|_| {
            Ok(QueryAccountResponse {
                account: Some(Any {
                    type_url: "wrong_type".to_string(),
                    value: vec![1, 2, 3, 4, 5],
                }),
            })
        });
        let mut broadcaster = init_validated_broadcaster(
            client,
            signer,
            key_id,
            PublicKey::new_secp256k1(priv_key.verifying_key().to_sec1_bytes()).unwrap(),
        )
        .await;

        for report in [
            broadcaster.broadcast(vec![dummy_msg()]).await.unwrap_err(),
            Broadcaster::estimate_fee(&mut broadcaster, vec![dummy_msg()])
                .await
                .unwrap_err(),
        ] {
            assert!(matches!(
                report.current_context(),
                Error::MalformedResponse { .. }
            ));
        }
    }

    fn init_unvalidated_broadcaster(
        client: MockCosmosClient,
        signer: MockMultisig,
        key_id: String,
        pub_key: PublicKey,
    ) -> UnvalidatedBasicBroadcaster<MockCosmosClient, MockMultisig> {
        UnvalidatedBasicBroadcaster::builder()
            .client(client)
            .signer(signer)
            .address_prefix(PREFIX.to_string())
            .pub_key((key_id, CosmosPublicKey::try_from(pub_key).unwrap()))
            .config(Config::default())
            .build()
    }

    async fn init_validated_broadcaster(
        client: MockCosmosClient,
        signer: MockMultisig,
        key_id: String,
        pub_key: PublicKey,
    ) -> BasicBroadcaster<MockCosmosClient, MockMultisig> {
        init_unvalidated_broadcaster(client, signer, key_id, pub_key)
            .validate_fee_denomination()
            .await
            .unwrap()
    }

    fn setup_broadcast_mock(mut client: MockCosmosClient) -> MockCosmosClient {
        client.expect_simulate().returning(|_| {
            Ok(SimulateResponse {
                gas_info: Some(GasInfo {
                    gas_wanted: 1000,
                    gas_used: 500,
                }),
                result: None,
            })
        });
        client.expect_broadcast_tx().returning(|_| {
            Ok(BroadcastTxResponse {
                tx_response: Some(TxResponse::default()),
            })
        });
        client.expect_tx().returning(|_| {
            Ok(GetTxResponse {
                tx_response: Some(TxResponse {
                    code: 0,
                    ..TxResponse::default()
                }),
                ..GetTxResponse::default()
            })
        });

        client
    }

    fn setup_balance_mock(mut client: MockCosmosClient, known_denom: &Denom) -> MockCosmosClient {
        let known_denom = known_denom.clone();

        client.expect_balance().returning(move |request| {
            if request.denom.eq(known_denom.as_ref()) {
                Ok(QueryBalanceResponse {
                    balance: Some(
                        Coin {
                            amount: 1,
                            denom: known_denom.clone(),
                        }
                        .into(),
                    ),
                })
            } else {
                Ok(QueryBalanceResponse {
                    balance: Some(
                        Coin {
                            amount: 0,
                            denom: request.denom.parse().unwrap(),
                        }
                        .into(),
                    ),
                })
            }
        });

        client
    }

    fn setup_account_mock(mut client: MockCosmosClient, priv_key: &SigningKey) -> MockCosmosClient {
        let pub_key = PublicKey::new_secp256k1(priv_key.verifying_key().to_sec1_bytes()).unwrap();
        let address: TMAddress = CosmosPublicKey::try_from(pub_key)
            .unwrap()
            .account_id(PREFIX)
            .unwrap()
            .into();
        let account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number: 7,
            sequence: 0,
        };

        client.expect_account().returning(move |request| {
            if request.address == address.to_string() {
                Ok(QueryAccountResponse {
                    account: Some(Any::from_msg(&account).unwrap()),
                })
            } else {
                Ok(QueryAccountResponse { account: None })
            }
        });

        client
    }

    // signs a digest if the public key matches the given private key
    fn init_mock_signer(key_id: &str, priv_key: &SigningKey) -> MockMultisig {
        let key_id = key_id.to_string();
        let priv_key = priv_key.clone();
        let pub_key = PublicKey::new_secp256k1(priv_key.verifying_key().to_sec1_bytes()).unwrap();

        let mut signer = MockMultisig::default();
        signer
            .expect_sign()
            .returning(move |actual_key_uid, data, actual_pub_key, _| {
                assert_eq!(actual_key_uid, &key_id);
                assert_eq!(actual_pub_key, pub_key);

                let (signature, _) = priv_key
                    .sign_prehash_recoverable(<Vec<u8>>::from(data).as_slice())
                    .unwrap();

                Ok(signature.to_vec())
            });
        signer
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
