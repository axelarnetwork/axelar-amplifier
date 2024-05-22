use std::convert::TryInto;
use std::ops::Mul;
use std::time::Duration;
use std::{cmp, thread};

use async_trait::async_trait;
use cosmos_sdk_proto::cosmos::base::abci::v1beta1::TxResponse;
use cosmos_sdk_proto::cosmos::tx::v1beta1::{
    BroadcastMode, BroadcastTxRequest, GetTxRequest, GetTxResponse, SimulateRequest,
};
use cosmos_sdk_proto::traits::MessageExt;
use cosmrs::tendermint::chain::Id;
use cosmrs::tx::Fee;
use cosmrs::{Coin, Gas};
use error_stack::{FutureExt, Report, Result, ResultExt};
use futures::TryFutureExt;
use k256::sha2::{Digest, Sha256};
use mockall::automock;
use num_traits::cast;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tonic::Status;
use tracing::debug;
use tracing::info;
use typed_builder::TypedBuilder;
use valuable::Valuable;

use dec_coin::DecCoin;
use report::LoggableError;
use tx::Tx;

use crate::tm_address::{PublicKey, TMAddress};
use crate::tofnd::grpc::SharableEcdsaClient;

pub mod accounts;
pub mod clients;
mod dec_coin;
mod tx;

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
    #[error("failed to confirm tx inclusion in block")]
    TxConfirmation,
    #[error("failed to execute tx")]
    Execution { response: TxResponse },
    #[error("failed to query account information for address {address}")]
    QueryAccount { address: TMAddress },
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
            gas_adjustment: 1.0,
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
    async fn broadcast(&mut self, msgs: Vec<cosmrs::Any>) -> Result<TxResponse, Error>;
    async fn estimate_fee(&mut self, msgs: Vec<cosmrs::Any>) -> Result<Fee, Error>;
}

#[derive(TypedBuilder)]
pub struct BroadcastClient<T, Q> {
    client: T,
    signer: SharableEcdsaClient,
    query_client: Q,
    address: TMAddress,
    #[builder(default, setter(skip))]
    acc_sequence: Option<u64>,
    pub_key: (String, PublicKey),
    config: Config,
}

#[async_trait]
impl<T, Q> Broadcaster for BroadcastClient<T, Q>
where
    T: clients::BroadcastClient + Send,
    Q: clients::AccountQueryClient + Send,
{
    async fn broadcast(&mut self, msgs: Vec<cosmrs::Any>) -> Result<TxResponse, Error> {
        let (acc_number, acc_sequence) = self.acc_number_and_sequence().await?;
        let tx = Tx::builder()
            .msgs(msgs.clone())
            .fee(self.estimate_fee(msgs, acc_sequence).await?)
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

                self.signer
                    .sign(self.pub_key.0.as_str(), sign_digest.into(), &self.pub_key.1)
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
            .await?;
        let TxResponse {
            txhash: tx_hash, ..
        } = &response;

        info!(tx_hash, "broadcasted transaction");

        self.confirm_tx(tx_hash).await?;

        info!(tx_hash, "confirmed transaction");

        self.acc_sequence.replace(
            acc_sequence
                .checked_add(1)
                .expect("account sequence must be less than u64::MAX"),
        );
        Ok(response)
    }

    async fn estimate_fee(&mut self, msgs: Vec<cosmrs::Any>) -> Result<Fee, Error> {
        let (_, acc_sequence) = self.acc_number_and_sequence().await?;

        self.estimate_fee(msgs, acc_sequence).await
    }
}

impl<T, Q> BroadcastClient<T, Q>
where
    T: clients::BroadcastClient,
    Q: clients::AccountQueryClient,
{
    async fn acc_number_and_sequence(&mut self) -> Result<(u64, u64), Error> {
        let account = accounts::account(&mut self.query_client, &self.address)
            .await
            .change_context_lazy(|| Error::QueryAccount {
                address: self.address.clone(),
            })?;

        let acc_sequence = self.acc_sequence.insert(cmp::max(
            account.sequence,
            self.acc_sequence.unwrap_or_default(),
        ));

        Ok((account.account_number, *acc_sequence))
    }

    async fn estimate_fee(
        &mut self,
        msgs: Vec<cosmrs::Any>,
        acc_sequence: u64,
    ) -> Result<Fee, Error> {
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
                    amount: cast((gas_adj.mul(self.config.gas_price.amount)).ceil())
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

    async fn confirm_tx(&mut self, tx_hash: &str) -> Result<(), Error> {
        let mut result: Result<(), Status> = Ok(());

        for i in 0..self.config.tx_fetch_max_retries.saturating_add(1) {
            if i > 0 {
                thread::sleep(self.config.tx_fetch_interval)
            }

            let response = self
                .client
                .get_tx(GetTxRequest {
                    hash: tx_hash.to_string(),
                })
                .await;

            match evaluate_response(response) {
                ConfirmationResult::Success => {
                    if let Err(report) = result {
                        debug!(
                            err = LoggableError::from(&report).as_value(),
                            "tx confirmed after {} retries", i
                        )
                    }

                    return Ok(());
                }
                ConfirmationResult::Critical(err) => return Err(err.into()),
                ConfirmationResult::Retriable(err) => {
                    if let Err(result) = result.as_mut() {
                        result.extend_one(err);
                    } else {
                        result = Err(err);
                    }
                }
            };
        }

        result.change_context(Error::TxConfirmation)
    }
}

fn evaluate_response(response: Result<GetTxResponse, Status>) -> ConfirmationResult {
    match response {
        Err(err) => ConfirmationResult::Retriable(err),
        Ok(GetTxResponse {
            tx_response: None, ..
        }) => ConfirmationResult::Retriable(Report::new(Status::not_found("tx not found"))),
        Ok(GetTxResponse {
            tx_response: Some(response),
            ..
        }) => match response {
            TxResponse { code: 0, .. } => ConfirmationResult::Success,
            _ => ConfirmationResult::Critical(Error::Execution { response }),
        },
    }
}

enum ConfirmationResult {
    Success,
    Retriable(Report<Status>),
    Critical(Error),
}

#[cfg(test)]
mod tests {
    use cosmos_sdk_proto::cosmos::auth::v1beta1::{BaseAccount, QueryAccountResponse};
    use cosmos_sdk_proto::cosmos::base::abci::v1beta1::{GasInfo, TxResponse};
    use cosmos_sdk_proto::cosmos::tx::v1beta1::{GetTxResponse, SimulateResponse};
    use cosmos_sdk_proto::traits::MessageExt;
    use cosmos_sdk_proto::Any;
    use cosmrs::{bank::MsgSend, tx::Msg, AccountId};
    use ecdsa::SigningKey;
    use rand::rngs::OsRng;
    use tokio::test;
    use tonic::Status;

    use crate::broadcaster::clients::{MockAccountQueryClient, MockBroadcastClient};
    use crate::broadcaster::{BroadcastClient, Broadcaster, Config, Error};
    use crate::tm_address::{PublicKey, TMAddress};
    use crate::tofnd::grpc::{MockEcdsaClient, SharableEcdsaClient};
    use crate::PREFIX;

    #[test]
    async fn gas_estimation_call_failed() {
        let key_id = "key_uid";
        let priv_key = SigningKey::random(&mut OsRng);
        let pub_key: PublicKey = priv_key.verifying_key().into();
        let address: TMAddress = pub_key
            .account_id(PREFIX)
            .expect("failed to convert to account identifier")
            .into();
        let account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number: 7,
            sequence: 0,
        };

        let mut client = MockBroadcastClient::new();
        client
            .expect_simulate()
            .returning(|_| Err(Status::unavailable("unavailable service").into()));

        let signer = MockEcdsaClient::new();

        let mut query_client = MockAccountQueryClient::new();
        query_client.expect_account().returning(move |_| {
            Ok(QueryAccountResponse {
                account: Some(account.to_any().unwrap()),
            })
        });

        let mut broadcaster = BroadcastClient::builder()
            .client(client)
            .signer(SharableEcdsaClient::new(signer))
            .query_client(query_client)
            .address(address)
            .pub_key((key_id.to_string(), pub_key))
            .config(Config::default())
            .build();
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
        let key_id = "key_uid";
        let priv_key = SigningKey::random(&mut OsRng);
        let pub_key: PublicKey = priv_key.verifying_key().into();
        let address: TMAddress = pub_key
            .account_id(PREFIX)
            .expect("failed to convert to account identifier")
            .into();
        let account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number: 7,
            sequence: 0,
        };

        let mut client = MockBroadcastClient::new();
        client.expect_simulate().returning(|_| {
            Ok(SimulateResponse {
                gas_info: None,
                result: None,
            })
        });

        let signer = MockEcdsaClient::new();

        let mut query_client = MockAccountQueryClient::new();
        query_client.expect_account().returning(move |_| {
            Ok(QueryAccountResponse {
                account: Some(account.to_any().unwrap()),
            })
        });

        let mut broadcaster = BroadcastClient::builder()
            .client(client)
            .signer(SharableEcdsaClient::new(signer))
            .query_client(query_client)
            .address(address)
            .pub_key((key_id.to_string(), pub_key))
            .config(Config::default())
            .build();
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
        let key_id = "key_uid";
        let priv_key = SigningKey::random(&mut OsRng);
        let pub_key: PublicKey = priv_key.verifying_key().into();
        let address: TMAddress = pub_key
            .account_id(PREFIX)
            .expect("failed to convert to account identifier")
            .into();
        let account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number: 7,
            sequence: 0,
        };

        let mut client = MockBroadcastClient::new();
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
            .returning(|_| Err(Status::aborted("failed").into()));

        let mut signer = MockEcdsaClient::new();
        signer
            .expect_sign()
            .once()
            .returning(move |actual_key_uid, data, actual_pub_key| {
                assert_eq!(actual_key_uid, key_id);
                assert_eq!(actual_pub_key, &pub_key);

                let (signature, _) = priv_key
                    .sign_prehash_recoverable(<Vec<u8>>::from(data).as_slice())
                    .unwrap();

                Ok(signature.to_vec())
            });

        let mut query_client = MockAccountQueryClient::new();
        query_client.expect_account().returning(move |_| {
            Ok(QueryAccountResponse {
                account: Some(account.to_any().unwrap()),
            })
        });

        let mut broadcaster = BroadcastClient::builder()
            .client(client)
            .signer(SharableEcdsaClient::new(signer))
            .query_client(query_client)
            .address(address)
            .pub_key((key_id.to_string(), pub_key))
            .config(Config::default())
            .build();
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
    async fn tx_confirmation_failed() {
        let key_id = "key_uid";
        let priv_key = SigningKey::random(&mut OsRng);
        let pub_key: PublicKey = priv_key.verifying_key().into();
        let address: TMAddress = pub_key
            .account_id(PREFIX)
            .expect("failed to convert to account identifier")
            .into();
        let account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number: 7,
            sequence: 0,
        };

        let mut client = MockBroadcastClient::new();
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
            .returning(|_| Ok(TxResponse::default()));
        client
            .expect_get_tx()
            .times((Config::default().tx_fetch_max_retries + 1) as usize)
            .returning(|_| Err(Status::deadline_exceeded("time out").into()));

        let mut signer = MockEcdsaClient::new();
        signer
            .expect_sign()
            .once()
            .returning(move |actual_key_uid, data, actual_pub_key| {
                assert_eq!(actual_key_uid, key_id);
                assert_eq!(actual_pub_key, &pub_key);

                let (signature, _) = priv_key
                    .sign_prehash_recoverable(<Vec<u8>>::from(data).as_slice())
                    .unwrap();

                Ok(signature.to_vec())
            });

        let mut query_client = MockAccountQueryClient::new();
        query_client.expect_account().returning(move |_| {
            Ok(QueryAccountResponse {
                account: Some(account.to_any().unwrap()),
            })
        });

        let mut broadcaster = BroadcastClient::builder()
            .client(client)
            .signer(SharableEcdsaClient::new(signer))
            .query_client(query_client)
            .address(address)
            .pub_key((key_id.to_string(), pub_key))
            .config(Config::default())
            .build();
        let msgs = vec![dummy_msg()];

        assert!(matches!(
            broadcaster
                .broadcast(msgs)
                .await
                .unwrap_err()
                .current_context(),
            Error::TxConfirmation
        ));
    }

    #[test]
    async fn tx_execution_failed() {
        let key_id = "key_uid";
        let priv_key = SigningKey::random(&mut OsRng);
        let pub_key: PublicKey = priv_key.verifying_key().into();
        let address: TMAddress = pub_key
            .account_id(PREFIX)
            .expect("failed to convert to account identifier")
            .into();
        let account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number: 7,
            sequence: 0,
        };

        let mut client = MockBroadcastClient::new();
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
            .returning(|_| Ok(TxResponse::default()));
        client.expect_get_tx().times(1).returning(|_| {
            Ok(GetTxResponse {
                tx_response: Some(TxResponse {
                    code: 32,
                    ..TxResponse::default()
                }),
                ..GetTxResponse::default()
            })
        });

        let mut signer = MockEcdsaClient::new();
        signer
            .expect_sign()
            .once()
            .returning(move |actual_key_uid, data, actual_pub_key| {
                assert_eq!(actual_key_uid, key_id);
                assert_eq!(actual_pub_key, &pub_key);

                let (signature, _) = priv_key
                    .sign_prehash_recoverable(<Vec<u8>>::from(data).as_slice())
                    .unwrap();

                Ok(signature.to_vec())
            });

        let mut query_client = MockAccountQueryClient::new();
        query_client.expect_account().returning(move |_| {
            Ok(QueryAccountResponse {
                account: Some(account.to_any().unwrap()),
            })
        });

        let mut broadcaster = BroadcastClient::builder()
            .client(client)
            .signer(SharableEcdsaClient::new(signer))
            .query_client(query_client)
            .address(address)
            .pub_key((key_id.to_string(), pub_key))
            .config(Config::default())
            .build();
        let msgs = vec![dummy_msg()];

        assert!(matches!(
            broadcaster
                .broadcast(msgs)
                .await
                .unwrap_err()
                .current_context(),
            Error::Execution {
                response: TxResponse { code: 32, .. }
            }
        ));
    }

    #[test]
    async fn broadcast_confirmed() {
        let key_id = "key_uid";
        let priv_key = SigningKey::random(&mut OsRng);
        let pub_key: PublicKey = priv_key.verifying_key().into();
        let address: TMAddress = pub_key
            .account_id(PREFIX)
            .expect("failed to convert to account identifier")
            .into();
        let account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number: 7,
            sequence: 0,
        };

        let mut client = MockBroadcastClient::new();
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
            .returning(|_| Ok(TxResponse::default()));
        client.expect_get_tx().returning(|_| {
            Ok(GetTxResponse {
                tx_response: Some(TxResponse {
                    code: 0,
                    ..TxResponse::default()
                }),
                ..GetTxResponse::default()
            })
        });

        let mut signer = MockEcdsaClient::new();
        signer
            .expect_sign()
            .once()
            .returning(move |actual_key_uid, data, actual_pub_key| {
                assert_eq!(actual_key_uid, key_id);
                assert_eq!(actual_pub_key, &pub_key);

                let (signature, _) = priv_key
                    .sign_prehash_recoverable(<Vec<u8>>::from(data).as_slice())
                    .unwrap();

                Ok(signature.to_vec())
            });

        let mut query_client = MockAccountQueryClient::new();
        query_client.expect_account().returning(move |_| {
            Ok(QueryAccountResponse {
                account: Some(account.to_any().unwrap()),
            })
        });

        let mut broadcaster = BroadcastClient::builder()
            .client(client)
            .signer(SharableEcdsaClient::new(signer))
            .query_client(query_client)
            .address(address)
            .pub_key((key_id.to_string(), pub_key))
            .config(Config::default())
            .build();
        let msgs = vec![dummy_msg()];

        assert_eq!(broadcaster.acc_sequence, None);
        assert!(broadcaster.broadcast(msgs).await.is_ok());
        assert_eq!(broadcaster.acc_sequence, Some(1));
    }

    #[test]
    async fn broadcast_confirmed_in_mem_acc_sequence_mismatch_with_on_chain() {
        let key_id = "key_uid";
        let priv_key = SigningKey::random(&mut OsRng);
        let pub_key: PublicKey = priv_key.verifying_key().into();
        let address: TMAddress = pub_key
            .account_id(PREFIX)
            .expect("failed to convert to account identifier")
            .into();
        let mut account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number: 7,
            sequence: 0,
        };

        let mut client = MockBroadcastClient::new();
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
            .returning(|_| Ok(TxResponse::default()));
        client.expect_get_tx().returning(|_| {
            Ok(GetTxResponse {
                tx_response: Some(TxResponse {
                    code: 0,
                    ..TxResponse::default()
                }),
                ..GetTxResponse::default()
            })
        });

        let mut signer = MockEcdsaClient::new();
        signer
            .expect_sign()
            .times(3)
            .returning(move |actual_key_uid, data, actual_pub_key| {
                assert_eq!(actual_key_uid, key_id);
                assert_eq!(actual_pub_key, &pub_key);

                let (signature, _) = priv_key
                    .sign_prehash_recoverable(<Vec<u8>>::from(data).as_slice())
                    .unwrap();

                Ok(signature.to_vec())
            });

        let mut query_client = MockAccountQueryClient::new();
        let mut call_count = 0;
        query_client.expect_account().returning(move |_| {
            call_count += 1;

            match call_count {
                1 => {
                    account.sequence = 0;
                }
                2 => {
                    account.sequence = 10;
                }
                _ => {
                    account.sequence = 0;
                }
            }

            Ok(QueryAccountResponse {
                account: Some(account.to_any().unwrap()),
            })
        });

        let mut broadcaster = BroadcastClient::builder()
            .client(client)
            .signer(SharableEcdsaClient::new(signer))
            .query_client(query_client)
            .address(address)
            .pub_key((key_id.to_string(), pub_key))
            .config(Config::default())
            .build();

        assert_eq!(broadcaster.acc_sequence, None);
        assert!(broadcaster.broadcast(vec![dummy_msg()]).await.is_ok());
        assert_eq!(broadcaster.acc_sequence, Some(1));
        assert!(broadcaster.broadcast(vec![dummy_msg()]).await.is_ok());
        assert_eq!(broadcaster.acc_sequence, Some(11));
        assert!(broadcaster.broadcast(vec![dummy_msg()]).await.is_ok());
        assert_eq!(broadcaster.acc_sequence, Some(12));
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
