use std::time::Duration;

use axelar_wasm_std::FnExt;
use cosmrs::proto::cosmos::tx::v1beta1::{GetTxRequest, GetTxResponse};
use error_stack::{report, Report, Result};
use futures::{StreamExt, TryFutureExt};
use thiserror::Error;
use tokio::sync::{mpsc, Mutex};
use tokio::time;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use tracing::error;

use super::cosmos;

#[derive(Debug, PartialEq)]
pub enum TxStatus {
    Success,
    Failure,
}

impl From<u32> for TxStatus {
    fn from(code: u32) -> Self {
        match code {
            0 => Self::Success,
            _ => Self::Failure,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct TxResponse {
    pub status: TxStatus,
    pub response: cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse,
}

impl From<cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse> for TxResponse {
    fn from(response: cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse) -> Self {
        Self {
            status: response.code.into(),
            response,
        }
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed confirming tx due to tx not found: {tx_hash}")]
    Confirmation { tx_hash: String },
    #[error("failed confirming tx due to grpc error {status}: {tx_hash}")]
    Grpc { status: Status, tx_hash: String },
    #[error("failed sending tx response")]
    SendTxRes(#[from] Box<mpsc::error::SendError<TxResponse>>),
}

enum ConfirmationResult {
    Confirmed(Box<TxResponse>),
    NotFound,
    GRPCError(Status),
}

pub struct TxConfirmer<T>
where
    T: cosmos::BroadcastClient,
{
    client: T,
    sleep: Duration,
    max_attempts: u32,
    tx_hash_receiver: mpsc::Receiver<String>,
    tx_res_sender: mpsc::Sender<TxResponse>,
}

impl<T> TxConfirmer<T>
where
    T: cosmos::BroadcastClient,
{
    pub fn new(
        client: T,
        sleep: Duration,
        max_attempts: u32,
        tx_hash_receiver: mpsc::Receiver<String>,
        tx_res_sender: mpsc::Sender<TxResponse>,
    ) -> Self {
        Self {
            client,
            sleep,
            max_attempts,
            tx_hash_receiver,
            tx_res_sender,
        }
    }

    pub async fn run(self) -> Result<(), Error> {
        let Self {
            client,
            sleep,
            max_attempts,
            tx_hash_receiver,
            tx_res_sender,
        } = self;
        let limit = tx_hash_receiver.capacity();
        let client = Mutex::new(client);
        let mut tx_hash_stream = ReceiverStream::new(tx_hash_receiver)
            .map(|tx_hash| {
                confirm_tx(&client, tx_hash, sleep, max_attempts).and_then(|tx| async {
                    tx_res_sender
                        .send(tx)
                        .await
                        .map_err(Box::new)
                        .map_err(Into::into)
                        .map_err(Report::new)
                })
            })
            .buffer_unordered(limit);

        while let Some(res) = tx_hash_stream.next().await {
            res?;
        }

        Ok(())
    }
}

async fn confirm_tx<T>(
    client: &Mutex<T>,
    tx_hash: String,
    sleep: Duration,
    attempts: u32,
) -> Result<TxResponse, Error>
where
    T: cosmos::BroadcastClient,
{
    for i in 0..attempts {
        let req = GetTxRequest {
            hash: tx_hash.clone(),
        };

        match client
            .lock()
            .await
            .get_tx(req)
            .await
            .then(evaluate_tx_response)
        {
            ConfirmationResult::Confirmed(tx) => return Ok(*tx),
            ConfirmationResult::NotFound if i == attempts.saturating_sub(1) => {
                return Err(report!(Error::Confirmation { tx_hash }))
            }
            ConfirmationResult::GRPCError(status) if i == attempts.saturating_sub(1) => {
                return Err(report!(Error::Grpc { status, tx_hash }))
            }
            _ => time::sleep(sleep).await,
        }
    }

    unreachable!("confirmation loop should have returned by now")
}

fn evaluate_tx_response(
    response: core::result::Result<GetTxResponse, Status>,
) -> ConfirmationResult {
    match response {
        Err(status) => ConfirmationResult::GRPCError(status),
        Ok(GetTxResponse {
            tx_response: None, ..
        }) => ConfirmationResult::NotFound,
        Ok(GetTxResponse {
            tx_response: Some(response),
            ..
        }) => ConfirmationResult::Confirmed(Box::new(response.into())),
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use cosmrs::proto::cosmos::tx::v1beta1::GetTxRequest;
    use mockall::predicate;
    use tokio::sync::mpsc;
    use tokio::test;

    use super::{Error, TxConfirmer, TxResponse, TxStatus};
    use crate::broadcaster::cosmos::MockBroadcastClient;

    #[test]
    async fn should_confirm_successful_tx_and_send_it_back() {
        let tx_hash = "tx_hash".to_string();
        let tx_response = cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse {
            code: 0,
            txhash: tx_hash.clone(),
            ..Default::default()
        };
        let tx_res = cosmrs::proto::cosmos::tx::v1beta1::GetTxResponse {
            tx_response: Some(tx_response.clone()),
            ..Default::default()
        };

        let mut client = MockBroadcastClient::new();
        client
            .expect_get_tx()
            .with(predicate::eq(GetTxRequest {
                hash: tx_hash.clone(),
            }))
            .return_once(|_| Ok(tx_res));

        let sleep = Duration::from_secs(5);
        let max_attempts = 3;
        let (tx_confirmer_sender, tx_confirmer_receiver) = mpsc::channel(100);
        let (tx_res_sender, mut tx_res_receiver) = mpsc::channel(100);

        let tx_confirmer = TxConfirmer::new(
            client,
            sleep,
            max_attempts,
            tx_confirmer_receiver,
            tx_res_sender,
        );
        let handle = tokio::spawn(tx_confirmer.run());

        tx_confirmer_sender.send(tx_hash).await.unwrap();
        assert_eq!(
            tx_res_receiver.recv().await.unwrap(),
            TxResponse {
                status: TxStatus::Success,
                response: tx_response
            }
        );
        drop(tx_confirmer_sender);
        assert!(handle.await.unwrap().is_ok());
    }

    #[test]
    async fn should_confirm_failed_tx_and_send_it_back() {
        let tx_hash = "tx_hash".to_string();
        let tx_response = cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse {
            code: 1,
            txhash: tx_hash.clone(),
            ..Default::default()
        };
        let tx_res = cosmrs::proto::cosmos::tx::v1beta1::GetTxResponse {
            tx_response: Some(tx_response.clone()),
            ..Default::default()
        };

        let mut client = MockBroadcastClient::new();
        client
            .expect_get_tx()
            .with(predicate::eq(GetTxRequest {
                hash: tx_hash.clone(),
            }))
            .return_once(|_| Ok(tx_res));

        let sleep = Duration::from_secs(5);
        let max_attempts = 3;
        let (tx_confirmer_sender, tx_confirmer_receiver) = mpsc::channel(100);
        let (tx_res_sender, mut tx_res_receiver) = mpsc::channel(100);

        let tx_confirmer = TxConfirmer::new(
            client,
            sleep,
            max_attempts,
            tx_confirmer_receiver,
            tx_res_sender,
        );
        let handle = tokio::spawn(tx_confirmer.run());

        tx_confirmer_sender.send(tx_hash).await.unwrap();
        assert_eq!(
            tx_res_receiver.recv().await.unwrap(),
            TxResponse {
                status: TxStatus::Failure,
                response: tx_response
            }
        );
        drop(tx_confirmer_sender);
        assert!(handle.await.unwrap().is_ok());
    }

    #[test]
    async fn should_retry_when_tx_is_not_found() {
        let tx_hash = "tx_hash".to_string();

        let mut client = MockBroadcastClient::new();
        client
            .expect_get_tx()
            .with(predicate::eq(GetTxRequest {
                hash: tx_hash.clone(),
            }))
            .times(3)
            .returning(|_| Ok(cosmrs::proto::cosmos::tx::v1beta1::GetTxResponse::default()));

        let sleep = Duration::from_millis(100);
        let max_attempts = 3;
        let (tx_confirmer_sender, tx_confirmer_receiver) = mpsc::channel(100);
        let (tx_res_sender, _tx_res_receiver) = mpsc::channel(100);

        let tx_confirmer = TxConfirmer::new(
            client,
            sleep,
            max_attempts,
            tx_confirmer_receiver,
            tx_res_sender,
        );
        let handle = tokio::spawn(tx_confirmer.run());

        tx_confirmer_sender.send(tx_hash.clone()).await.unwrap();
        assert!(matches!(
            handle.await.unwrap().unwrap_err().current_context(),
            Error::Confirmation { tx_hash: actual } if *actual == tx_hash
        ));
    }

    #[test]
    async fn should_retry_when_grpc_error() {
        let tx_hash = "tx_hash".to_string();

        let mut client = MockBroadcastClient::new();
        client
            .expect_get_tx()
            .with(predicate::eq(GetTxRequest {
                hash: tx_hash.clone(),
            }))
            .times(3)
            .returning(|_| {
                Err(tonic::Status::new(
                    tonic::Code::Internal,
                    "internal server error",
                ))
            });

        let sleep = Duration::from_millis(100);
        let max_attempts = 3;
        let (tx_confirmer_sender, tx_confirmer_receiver) = mpsc::channel(100);
        let (tx_res_sender, _tx_res_receiver) = mpsc::channel(100);

        let tx_confirmer = TxConfirmer::new(
            client,
            sleep,
            max_attempts,
            tx_confirmer_receiver,
            tx_res_sender,
        );
        let handle = tokio::spawn(tx_confirmer.run());

        tx_confirmer_sender.send(tx_hash.clone()).await.unwrap();
        assert!(matches!(
            handle.await.unwrap().unwrap_err().current_context(),
            Error::Grpc { tx_hash: actual, status } if *actual == tx_hash && status.code() == tonic::Code::Internal
        ));
    }
}
