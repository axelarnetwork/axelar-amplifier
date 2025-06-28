use cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse;
use error_stack::{report, ResultExt};
use futures::StreamExt;
use report::LoggableError;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, info, instrument, warn};
use valuable::Valuable;

use crate::asyncutil::future::{with_retry, RetryPolicy};
use crate::cosmos;

// Maximum number of transaction confirmations to process concurrently.
// - Controls parallelism when confirming transactions
// - Higher values increase throughput for confirming many transactions
// - Lower values reduce resource consumption
// - Balance based on network capacity and system resources
const TX_CONFIRMATION_BUFFER_SIZE: usize = 10;
// Maximum capacity of the transaction confirmation queue.
// - Determines how many transactions can be queued for confirmation before backpressure
// - Larger values provide more buffering for high-volume transaction periods
// - Too small may cause confirmation requests to be dropped during traffic spikes
// - Too large may consume excessive memory if confirmations become backlogged
const TX_CONFIRMATION_QUEUE_CAP: usize = 1000;

type Result<T> = error_stack::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("tx {0} not found on chain")]
    NotFound(String),
    #[error("tx {} failed on chain", .0.txhash)]
    FailureOnChain(Box<TxResponse>),
    #[error("failed to query for tx {0}")]
    TxQuery(String),
}

/// Client interface for submitting transaction hashes to be confirmed by a `TxConfirmer`.
/// Allows external components to request transaction confirmation tracking in a decoupled manner.
pub type TxConfirmerClient = mpsc::Sender<String>;

/// Component responsible for confirming transactions on a Cosmos blockchain.
/// Monitors transaction execution status by querying the chain until transactions
/// are confirmed as successful or have definitively failed.
///
/// # Type Parameters
/// * `T` - A Cosmos client that can query transaction status on the blockchain
pub struct TxConfirmer<T>
where
    T: cosmos::CosmosClient + Clone,
{
    rx: mpsc::Receiver<String>,
    client: T,
    retry_policy: RetryPolicy,
}

impl<T> TxConfirmer<T>
where
    T: cosmos::CosmosClient + Clone,
{
    /// Creates a new transaction confirmer with the specified Cosmos client and retry policy.
    ///
    /// # Parameters
    /// * `client` - Cosmos client for querying transaction status
    /// * `retry_policy` - Policy defining retry behavior for failed transaction queries
    ///
    /// # Returns
    /// A tuple containing the confirmer instance and a client for submitting transaction hashes
    pub fn new_confirmer_and_client(
        client: T,
        retry_policy: RetryPolicy,
    ) -> (Self, TxConfirmerClient) {
        let (tx, rx) = mpsc::channel(TX_CONFIRMATION_QUEUE_CAP);
        let confirmer = Self {
            rx,
            client,
            retry_policy,
        };

        (confirmer, tx)
    }

    #[instrument(skip_all)]
    /// Starts the transaction confirmation process, continuously monitoring submitted transaction hashes.
    ///
    /// Processes transaction hashes from the receiver channel, concurrently confirming
    /// up to `TX_CONFIRMATION_BUFFER_SIZE` transactions. For each transaction, it queries
    /// the blockchain repeatedly according to the retry policy until the transaction
    /// is confirmed or definitely failed.
    ///
    /// # Returns
    /// A Result indicating whether the confirmer completed successfully
    pub async fn run(self) -> Result<()> {
        let Self {
            rx,
            client,
            retry_policy,
        } = self;
        let mut stream = ReceiverStream::new(rx)
            .inspect(|tx_hash| info!(tx_hash, "received tx hash to confirm"))
            .map(|tx_hash| confirm_tx(&client, tx_hash, retry_policy))
            .buffer_unordered(TX_CONFIRMATION_BUFFER_SIZE);

        while let Some(result) = stream.next().await {
            log_confirm_tx_result(result);
        }

        Ok(())
    }
}

async fn confirm_tx<T>(client: &T, tx_hash: String, retry_policy: RetryPolicy) -> Result<TxResponse>
where
    T: cosmos::CosmosClient + Clone,
{
    debug!(tx_hash, "confirming tx");

    let res = with_retry(|| tx(client.clone(), tx_hash.clone()), retry_policy).await?;

    match res.code {
        0 => Ok(res),
        _ => Err(report!(Error::FailureOnChain(Box::new(res)))),
    }
}

async fn tx<T>(mut client: T, tx_hash: String) -> Result<TxResponse>
where
    T: cosmos::CosmosClient,
{
    cosmos::tx(&mut client, &tx_hash)
        .await
        .change_context_lazy(|| Error::TxQuery(tx_hash.clone()))?
        .ok_or(report!(Error::NotFound(tx_hash)))
}

fn log_confirm_tx_result(result: Result<TxResponse>) {
    match result {
        Ok(res) => info!(tx_hash = res.txhash, "tx succeeded on chain"),
        Err(err) => match err.current_context() {
            Error::FailureOnChain(res) => {
                warn!(
                    err = LoggableError::from(&err).as_value(),
                    tx_hash = res.txhash,
                    "tx failed on chain"
                )
            }
            Error::NotFound(tx_hash) => {
                warn!(
                    err = LoggableError::from(&err).as_value(),
                    tx_hash, "tx not found on chain"
                )
            }
            Error::TxQuery(tx_hash) => {
                warn!(
                    err = LoggableError::from(&err).as_value(),
                    tx_hash, "failed to query for tx"
                )
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use cosmos_sdk_proto::cosmos::base::abci::v1beta1::TxResponse;
    use cosmos_sdk_proto::cosmos::tx::v1beta1::{GetTxRequest, GetTxResponse};
    use mockall::predicate;
    use report::ErrorExt;
    use tonic::Status;
    use tracing_test::traced_test;

    use crate::asyncutil::future::RetryPolicy;
    use crate::cosmos;

    #[tokio::test]
    #[traced_test]
    async fn tx_confirmer_should_confirm_tx_that_succeed_on_chain() {
        let tx_hash = "tx_hash";
        let retry_policy = RetryPolicy::repeat_constant(Duration::from_millis(500), 3);

        let mut client = cosmos::MockCosmosClient::default();
        client.expect_clone().return_once(|| {
            let mut client = cosmos::MockCosmosClient::default();
            client
                .expect_tx()
                .with(predicate::eq(GetTxRequest {
                    hash: tx_hash.to_string(),
                }))
                .return_once(|req| {
                    Ok(GetTxResponse {
                        tx_response: Some(TxResponse {
                            code: 0,
                            txhash: req.hash,
                            ..Default::default()
                        }),
                        ..Default::default()
                    })
                });

            client
        });

        let (confirmer, confirmer_client) =
            super::TxConfirmer::new_confirmer_and_client(client, retry_policy);
        confirmer_client.send(tx_hash.to_string()).await.unwrap();
        drop(confirmer_client);
        confirmer.run().await.unwrap();

        assert!(logs_contain("tx succeeded on chain"));
    }

    #[tokio::test]
    #[traced_test]
    async fn tx_confirmer_should_confirm_tx_that_failed_on_chain() {
        let tx_hash = "tx_hash";
        let retry_policy = RetryPolicy::repeat_constant(Duration::from_millis(500), 3);

        let mut client = cosmos::MockCosmosClient::default();
        client.expect_clone().return_once(|| {
            let mut client = cosmos::MockCosmosClient::default();
            client
                .expect_tx()
                .with(predicate::eq(GetTxRequest {
                    hash: tx_hash.to_string(),
                }))
                .return_once(|req| {
                    Ok(GetTxResponse {
                        tx_response: Some(TxResponse {
                            code: 1,
                            txhash: req.hash,
                            ..Default::default()
                        }),
                        ..Default::default()
                    })
                });

            client
        });

        let (confirmer, confirmer_client) =
            super::TxConfirmer::new_confirmer_and_client(client, retry_policy);
        confirmer_client.send(tx_hash.to_string()).await.unwrap();
        drop(confirmer_client);
        confirmer.run().await.unwrap();

        assert!(logs_contain("tx failed on chain"));
    }

    #[tokio::test]
    #[traced_test]
    async fn tx_confirmer_should_not_confirm_tx_that_cannot_be_found_on_chain() {
        let tx_hash = "tx_hash";
        let retry_policy = RetryPolicy::repeat_constant(Duration::from_millis(500), 3);

        let mut client = cosmos::MockCosmosClient::default();
        client.expect_clone().times(3).returning(|| {
            let mut client = cosmos::MockCosmosClient::default();
            client
                .expect_tx()
                .with(predicate::eq(GetTxRequest {
                    hash: tx_hash.to_string(),
                }))
                .return_once(|_| Ok(GetTxResponse::default()));

            client
        });

        let (confirmer, confirmer_client) =
            super::TxConfirmer::new_confirmer_and_client(client, retry_policy);
        confirmer_client.send(tx_hash.to_string()).await.unwrap();
        drop(confirmer_client);
        confirmer.run().await.unwrap();

        assert!(logs_contain("tx not found on chain"));
    }

    #[tokio::test]
    #[traced_test]
    async fn tx_confirmer_should_not_confirm_tx_that_cannot_be_queried() {
        let tx_hash = "tx_hash";
        let retry_policy = RetryPolicy::repeat_constant(Duration::from_millis(500), 3);

        let mut client = cosmos::MockCosmosClient::default();
        client.expect_clone().times(3).returning(|| {
            let mut client = cosmos::MockCosmosClient::default();
            client
                .expect_tx()
                .with(predicate::eq(GetTxRequest {
                    hash: tx_hash.to_string(),
                }))
                .return_once(|_| Err(Status::internal("internal error").into_report()));

            client
        });

        let (confirmer, confirmer_client) =
            super::TxConfirmer::new_confirmer_and_client(client, retry_policy);
        confirmer_client.send(tx_hash.to_string()).await.unwrap();
        drop(confirmer_client);
        confirmer.run().await.unwrap();

        assert!(logs_contain("failed to query for tx"));
    }
}
