use std::thread;
use std::time::Duration;

use async_trait::async_trait;
use cosmos_sdk_proto::cosmos::base::abci::v1beta1::TxResponse;
use cosmos_sdk_proto::cosmos::tx::v1beta1::{
    BroadcastMode, BroadcastTxRequest, GetTxRequest, GetTxResponse, SimulateRequest, TxRaw,
};
use cosmos_sdk_proto::traits::MessageExt;
use cosmrs::tendermint::chain::Id;
use cosmrs::tx::{BodyBuilder, Fee, SignDoc, SignerInfo};
use cosmrs::{Coin, Gas};
use derive_builder::Builder;
use error_stack::{FutureExt, IntoReport, IntoReportCompat, Report, Result, ResultExt};
use futures::TryFutureExt;
use mockall::automock;
use serde::Deserialize;
use thiserror::Error;
use tonic::Status;
use tracing::debug;
use tracing::info;
use valuable::Valuable;

use crate::report::LoggableError;
use crate::tofnd::grpc::SharableEcdsaClient;
use crate::types::PublicKey;
use dec_coin::DecCoin;
use fee::zero_fee;
use key::ECDSASigningKey;

pub mod accounts;
pub mod clients;
mod dec_coin;
mod fee;
pub mod key;

#[derive(Error, Debug)]
pub enum Error {
    #[error("tx marshaling failed")]
    TxMarshaling,
    #[error("failed to estimate gas")]
    GasEstimation,
    #[error("broadcast failed")]
    Broadcast,
    #[error("failed to confirm tx inclusion in block")]
    TxConfirmation,
    #[error("failed to execute tx")]
    ExecutionError { response: TxResponse },
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub chain_id: Id,
    pub tx_fetch_interval: Duration,
    pub tx_fetch_max_retries: u32,
    pub gas_adjustment: f64,
    pub gas_price: DecCoin,
    pub batch_gas_limit: Gas,
    pub queue_cap: usize,
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

#[derive(Builder)]
pub struct BroadcastClient<T>
where
    T: clients::BroadcastClient,
{
    client: T,
    #[allow(dead_code)]
    signer: SharableEcdsaClient,
    acc_number: u64,
    acc_sequence: u64,
    priv_key: ECDSASigningKey,
    #[allow(dead_code)]
    pub_key: (String, PublicKey),
    config: Config,
}

#[async_trait]
impl<T> Broadcaster for BroadcastClient<T>
where
    T: clients::BroadcastClient + Send + Sync,
{
    async fn broadcast(&mut self, msgs: Vec<cosmrs::Any>) -> Result<TxResponse, Error> {
        let fee = self.estimate_fee(msgs.clone()).await?;

        let tx_bytes = self.create_tx(msgs, fee)?;

        let response = self
            .client
            .broadcast_tx(tx_bytes)
            .change_context(Error::Broadcast)
            .await?;
        let TxResponse {
            height,
            txhash: tx_hash,
            ..
        } = &response;

        info!(height, tx_hash, "broadcasted transaction");

        self.confirm_tx(tx_hash).await?;

        info!(height, tx_hash, "confirmed transaction");

        self.acc_sequence += 1;
        Ok(response)
    }

    async fn estimate_fee(&mut self, msgs: Vec<cosmrs::Any>) -> Result<Fee, Error> {
        let sim_tx = self.create_sim_tx(msgs)?;

        self.estimate_gas(sim_tx).await.map(|gas| {
            let gas_adj = (gas as f64 * self.config.gas_adjustment) as u64;

            Fee::from_amount_and_gas(
                Coin {
                    amount: (gas_adj as f64 * self.config.gas_price.amount).ceil() as u128,
                    denom: self.config.gas_price.denom.clone().into(),
                },
                gas_adj,
            )
        })
    }
}

impl<T> BroadcastClient<T>
where
    T: clients::BroadcastClient,
{
    async fn estimate_gas(&mut self, tx_bytes: Vec<u8>) -> Result<u64, Error> {
        #[allow(deprecated)]
        self.client
            .simulate(SimulateRequest { tx: None, tx_bytes })
            .change_context(Error::GasEstimation)
            .and_then(|response| async {
                response
                    .gas_info
                    .map(|info| info.gas_used)
                    .ok_or(Error::GasEstimation)
                    .into_report()
            })
            .await
    }

    fn create_sim_tx<M>(&self, msgs: M) -> Result<Vec<u8>, Error>
    where
        M: IntoIterator<Item = cosmrs::Any>,
    {
        let body_bytes = BodyBuilder::new()
            .msgs(msgs)
            .finish()
            .into_bytes()
            .into_report()
            .change_context(Error::TxMarshaling)?;

        let auth_info_bytes =
            SignerInfo::single_direct(Some(self.priv_key.public_key()), self.acc_sequence)
                .auth_info(zero_fee())
                .into_bytes()
                .into_report()
                .change_context(Error::TxMarshaling)?;

        let raw = TxRaw {
            body_bytes,
            auth_info_bytes,
            // empty signature to pass validation
            signatures: vec![vec![0; 64]],
        };

        raw.to_bytes()
            .into_report()
            .change_context(Error::TxMarshaling)
    }

    pub fn create_tx<M>(&self, msgs: M, fee: Fee) -> Result<BroadcastTxRequest, Error>
    where
        M: IntoIterator<Item = cosmrs::Any>,
    {
        let body = BodyBuilder::new().msgs(msgs).finish();
        let auth_info =
            SignerInfo::single_direct(Some(self.priv_key.public_key()), self.acc_sequence)
                .auth_info(fee);

        SignDoc::new(&body, &auth_info, &self.config.chain_id, self.acc_number)
            .and_then(|sign_doc| sign_doc.sign(&((&self.priv_key).into())))
            .and_then(|tx| tx.to_bytes())
            .map(|tx| BroadcastTxRequest {
                tx_bytes: tx,
                mode: BroadcastMode::Sync as i32,
            })
            .into_report()
            .change_context(Error::TxMarshaling)
    }

    async fn confirm_tx(&mut self, tx_hash: &str) -> Result<(), Error> {
        let mut result: Result<(), Status> = Ok(());

        for i in 0..self.config.tx_fetch_max_retries + 1 {
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
                ConfirmationResult::Critical(err) => return Err(err).into_report(),
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
            _ => ConfirmationResult::Critical(Error::ExecutionError { response }),
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
    use cosmos_sdk_proto::cosmos::base::abci::v1beta1::{GasInfo, TxResponse};
    use cosmos_sdk_proto::cosmos::tx::v1beta1::{GetTxResponse, SimulateResponse};
    use cosmos_sdk_proto::Any;
    use cosmrs::{bank::MsgSend, tx::Msg, AccountId};
    use error_stack::IntoReport;
    use tokio::test;
    use tonic::Status;

    use crate::broadcaster::clients::MockBroadcastClient;
    use crate::broadcaster::key::ECDSASigningKey;
    use crate::broadcaster::{BroadcastClient, Broadcaster, Config, Error};
    use crate::tofnd::grpc::{MockEcdsaClient, SharableEcdsaClient};

    #[test]
    async fn gas_estimation_call_failed() {
        let mut client = MockBroadcastClient::new();
        client
            .expect_simulate()
            .returning(|_| Err(Status::unavailable("unavailable service")).into_report());
        let signer = MockEcdsaClient::new();

        let priv_key = ECDSASigningKey::random();
        let pub_key = priv_key.public_key();
        let mut broadcaster = BroadcastClient {
            client,
            signer: SharableEcdsaClient::new(signer),
            acc_number: 0,
            acc_sequence: 0,
            priv_key,
            pub_key: ("key_uid".into(), pub_key),
            config: Config::default(),
        };
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
        let mut client = MockBroadcastClient::new();

        client.expect_simulate().returning(|_| {
            Ok(SimulateResponse {
                gas_info: None,
                result: None,
            })
        });
        let signer = MockEcdsaClient::new();

        let priv_key = ECDSASigningKey::random();
        let pub_key = priv_key.public_key();
        let mut broadcaster = BroadcastClient {
            client,
            signer: SharableEcdsaClient::new(signer),
            acc_number: 0,
            acc_sequence: 0,
            priv_key,
            pub_key: ("key_uid".into(), pub_key),
            config: Config::default(),
        };
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
            .returning(|_| Err(Status::aborted("failed")).into_report());
        let signer = MockEcdsaClient::new();

        let priv_key = ECDSASigningKey::random();
        let pub_key = priv_key.public_key();
        let mut broadcaster = BroadcastClient {
            client,
            signer: SharableEcdsaClient::new(signer),
            acc_number: 0,
            acc_sequence: 0,
            priv_key,
            pub_key: ("key_uid".into(), pub_key),
            config: Config::default(),
        };
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
            .returning(|_| Err(Status::deadline_exceeded("time out")).into_report());
        let signer = MockEcdsaClient::new();

        let priv_key = ECDSASigningKey::random();
        let pub_key = priv_key.public_key();
        let mut broadcaster = BroadcastClient {
            client,
            signer: SharableEcdsaClient::new(signer),
            acc_number: 0,
            acc_sequence: 0,
            priv_key,
            pub_key: ("key_uid".into(), pub_key),
            config: Config::default(),
        };
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
        let signer = MockEcdsaClient::new();

        let priv_key = ECDSASigningKey::random();
        let pub_key = priv_key.public_key();
        let mut broadcaster = BroadcastClient {
            client,
            signer: SharableEcdsaClient::new(signer),
            acc_number: 0,
            acc_sequence: 0,
            priv_key,
            pub_key: ("key_uid".into(), pub_key),
            config: Config::default(),
        };
        let msgs = vec![dummy_msg()];

        assert!(matches!(
            broadcaster
                .broadcast(msgs)
                .await
                .unwrap_err()
                .current_context(),
            Error::ExecutionError {
                response: TxResponse { code: 32, .. }
            }
        ));
    }

    #[test]
    async fn broadcast_confirmed() {
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
        let signer = MockEcdsaClient::new();

        let priv_key = ECDSASigningKey::random();
        let pub_key = priv_key.public_key();
        let mut broadcaster = BroadcastClient {
            client,
            signer: SharableEcdsaClient::new(signer),
            acc_number: 0,
            acc_sequence: 0,
            priv_key,
            pub_key: ("key_uid".into(), pub_key),
            config: Config::default(),
        };
        let msgs = vec![dummy_msg()];

        assert_eq!(broadcaster.acc_sequence, 0);
        assert!(broadcaster.broadcast(msgs).await.is_ok());
        assert_eq!(broadcaster.acc_sequence, 1);
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
