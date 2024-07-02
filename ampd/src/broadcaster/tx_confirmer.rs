use std::time::Duration;

use axelar_wasm_std::FnExt;
use cosmrs::proto::cosmos::tx::v1beta1::{GetTxRequest, GetTxResponse};
use error_stack::{report, Report, Result};
use thiserror::Error;
use tokio::{sync::mpsc, time::sleep};
use tonic::Status;
use tracing::error;

use super::cosmos;

#[derive(Debug)]
pub struct TxResponse {
    pub status: bool,
    pub response: cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse,
}

impl From<cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse> for TxResponse {
    fn from(response: cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse) -> Self {
        Self {
            status: response.code == 0,
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
    T: cosmos::BroadcastClient + Clone,
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

    pub async fn run(mut self) -> Result<(), Error> {
        while let Some(tx_hash) = self.tx_hash_receiver.recv().await {
            // TODO: handle tx not found instead of erroring out for the sake of re-try?
            let tx = self.confirm_tx(tx_hash.clone(), self.max_attempts).await?;

            self.tx_res_sender
                .send(tx)
                .await
                .map_err(Box::new)
                .map_err(Into::into)
                .map_err(Report::new)?;
        }

        Ok(())
    }

    async fn confirm_tx(&mut self, tx_hash: String, attempts: u32) -> Result<TxResponse, Error> {
        for i in 0..attempts {
            let req = GetTxRequest {
                hash: tx_hash.clone(),
            };

            match self.client.get_tx(req).await.then(evaluate_tx_response) {
                ConfirmationResult::Confirmed(tx) => return Ok(*tx),
                ConfirmationResult::NotFound if i == attempts.saturating_sub(1) => {
                    return Err(report!(Error::Confirmation { tx_hash }))
                }
                ConfirmationResult::GRPCError(status) if i == attempts.saturating_sub(1) => {
                    return Err(report!(Error::Grpc { status, tx_hash }))
                }
                _ => sleep(self.sleep).await,
            }
        }

        unreachable!("confirmation loop should have returned by now")
    }
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
