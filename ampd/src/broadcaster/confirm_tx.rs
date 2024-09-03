use std::sync::Arc;

use axelar_wasm_std::FnExt;
use cosmrs::proto::cosmos::tx::v1beta1::{GetTxRequest, GetTxResponse};
use error_stack::{bail, Report, Result};
use futures::{StreamExt, TryFutureExt};
use thiserror::Error;
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use tracing::error;

use super::cosmos;
use crate::asyncutil::future::{with_retry, RetryPolicy};

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

pub struct TxConfirmer<T>
where
    T: cosmos::BroadcastClient,
{
    client: T,
    retry_policy: RetryPolicy,
    tx_hash_receiver: mpsc::Receiver<String>,
    tx_res_sender: mpsc::Sender<TxResponse>,
}

impl<T> TxConfirmer<T>
where
    T: cosmos::BroadcastClient,
{
    pub fn new(
        client: T,
        retry_policy: RetryPolicy,
        tx_hash_receiver: mpsc::Receiver<String>,
        tx_res_sender: mpsc::Sender<TxResponse>,
    ) -> Self {
        Self {
            client,
            retry_policy,
            tx_hash_receiver,
            tx_res_sender,
        }
    }

    pub async fn run(self) -> Result<(), Error> {
        let Self {
            client,
            retry_policy,
            tx_hash_receiver,
            tx_res_sender,
        } = self;
        let limit = tx_hash_receiver.capacity();
        let client = Arc::new(Mutex::new(client));

        let mut tx_hash_stream = ReceiverStream::new(tx_hash_receiver)
            .map(|tx_hash| {
                // multiple instances of confirm_tx can be spawned due to buffer_unordered,
                // so we need to clone the client to avoid a deadlock
                confirm_tx_with_retry(client.clone(), tx_hash, retry_policy)
                    .and_then(|tx| async { send_response(&tx_res_sender, tx).await })
            })
            .buffer_unordered(limit);

        while let Some(res) = tx_hash_stream.next().await {
            res?;
        }

        Ok(())
    }
}

async fn confirm_tx_with_retry(
    client: Arc<Mutex<impl cosmos::BroadcastClient>>,
    tx_hash: String,
    retry_policy: RetryPolicy,
) -> Result<TxResponse, Error> {
    with_retry(|| confirm_tx(client.clone(), tx_hash.clone()), retry_policy).await
}

// do to limitations of lambdas and lifetime issues this needs to be a separate function
async fn confirm_tx(
    client: Arc<Mutex<impl cosmos::BroadcastClient>>,
    tx_hash: String,
) -> Result<TxResponse, Error> {
    let req = GetTxRequest {
        hash: tx_hash.clone(),
    };

    client
        .lock()
        .await
        .tx(req)
        .await
        .then(evaluate_tx_response(tx_hash))
}

fn evaluate_tx_response(
    tx_hash: String,
) -> impl Fn(core::result::Result<GetTxResponse, Status>) -> Result<TxResponse, Error> {
    move |response| match response {
        Err(status) => bail!(Error::Grpc {
            status,
            tx_hash: tx_hash.clone()
        }),
        Ok(GetTxResponse {
            tx_response: None, ..
        }) => bail!(Error::Confirmation {
            tx_hash: tx_hash.clone()
        }),
        Ok(GetTxResponse {
            tx_response: Some(response),
            ..
        }) => Ok(response.into()),
    }
}

async fn send_response(
    tx_res_sender: &mpsc::Sender<TxResponse>,
    tx: TxResponse,
) -> Result<(), Error> {
    tx_res_sender
        .send(tx)
        .await
        .map_err(Box::new)
        .map_err(Into::into)
        .map_err(Report::new)
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use cosmrs::proto::cosmos::tx::v1beta1::GetTxRequest;
    use mockall::predicate;
    use tokio::sync::mpsc;
    use tokio::test;

    use super::{Error, TxConfirmer, TxResponse, TxStatus};
    use crate::asyncutil::future::RetryPolicy;
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
            .expect_tx()
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
            RetryPolicy::RepeatConstant {
                sleep,
                max_attempts,
            },
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
            .expect_tx()
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
            RetryPolicy::RepeatConstant {
                sleep,
                max_attempts,
            },
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
            .expect_tx()
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
            RetryPolicy::RepeatConstant {
                sleep,
                max_attempts,
            },
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
            .expect_tx()
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
            RetryPolicy::RepeatConstant {
                sleep,
                max_attempts,
            },
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
