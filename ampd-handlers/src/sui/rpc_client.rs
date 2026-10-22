use std::collections::{HashMap, HashSet};
use std::time::Duration;

use ampd::monitoring;
use ampd::monitoring::metrics::Msg;
use ampd::url::Url;
use async_trait::async_trait;
use axelar_wasm_std::chain::ChainName;
use error_stack::{ensure, report, Report, ResultExt};
use futures::stream::{self, StreamExt, TryStreamExt};
use mockall::automock;
use sui_rpc::client::HeadersInterceptor;
use sui_rpc::field::{FieldMask, FieldMaskUtil};
use sui_rpc::proto::sui::rpc::v2::get_transaction_result::Result as Lookup;
use sui_rpc::proto::sui::rpc::v2::{
    BatchGetTransactionsRequest, ExecutedTransaction, GetTransactionResult,
};
use sui_sdk_types::Digest;
use thiserror::Error;
use tonic::metadata::{Ascii, MetadataKey, MetadataValue};
use tonic::Code;

use crate::sui::transaction::Transaction;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to create client")]
    Client,
    #[error("invalid rpc header")]
    Header,
    #[error("rpc call failed")]
    RpcCall,
    #[error("malformed rpc response")]
    MalformedResponse,
}

type Result<T> = error_stack::Result<T, Error>;

/// Digests per request; the node accepts at most 200.
const BATCH_SIZE: usize = 50;

/// A transaction may emit tens of megabytes of events, well past tonic's 4 MiB default.
const MAX_RESPONSE_BYTES: usize = 256 * 1024 * 1024;

/// Requests in flight at once, bounding the memory and node load a large poll can cause.
const MAX_CONCURRENT_REQUESTS: usize = 4;

#[automock]
#[async_trait]
pub trait SuiClient {
    async fn finalized_transaction_blocks(
        &self,
        digests: HashSet<Digest>,
    ) -> Result<HashMap<Digest, Transaction>>;
}

pub struct Client {
    client: sui_rpc::Client,
    timeout: Duration,
    monitoring_client: monitoring::Client,
    chain_name: ChainName,
}

impl Client {
    pub fn new(
        url: &Url,
        timeout: Duration,
        headers: HashMap<String, String>,
        monitoring_client: monitoring::Client,
        chain_name: ChainName,
    ) -> Result<Self> {
        let client = sui_rpc::Client::new(url.as_str())
            .change_context(Error::Client)?
            .with_max_decoding_message_size(MAX_RESPONSE_BYTES)
            .with_headers(headers_interceptor(headers)?);

        Ok(Self {
            client,
            timeout,
            monitoring_client,
            chain_name,
        })
    }

    /// One batch, refetched one transaction at a time when its response exceeds the
    /// receive limit, which a single transaction's events never do.
    async fn fetch(&self, digests: &[Digest]) -> Result<Vec<(Digest, Transaction)>> {
        match self.fetch_batch(digests).await {
            Err(err) if digests.len() > 1 && too_large(&err) => {
                let singles: Vec<_> = digests
                    .chunks(1)
                    .map(|digest| self.fetch_batch(digest))
                    .collect();
                stream::iter(singles)
                    .buffer_unordered(MAX_CONCURRENT_REQUESTS)
                    .try_concat()
                    .await
            }
            res => res,
        }
    }

    async fn fetch_batch(&self, digests: &[Digest]) -> Result<Vec<(Digest, Transaction)>> {
        let res = self.try_fetch_batch(digests).await;
        self.monitoring_client
            .metrics()
            .record_metric(Msg::RpcCall {
                chain_name: self.chain_name.clone(),
                success: res.is_ok(),
            });

        res
    }

    async fn try_fetch_batch(&self, digests: &[Digest]) -> Result<Vec<(Digest, Transaction)>> {
        let mut request = tonic::Request::new(
            BatchGetTransactionsRequest::default()
                .with_digests(digests.iter().map(Digest::to_string).collect())
                .with_read_mask(read_mask()),
        );
        request.set_timeout(self.timeout);

        // The client is a handle on a shared channel, so cloning it per call is cheap and
        // keeps `&self` here while `ledger_client` needs `&mut`.
        let mut ledger = self.client.clone().ledger_client();
        let response = ledger
            .batch_get_transactions(request)
            .await
            .change_context(Error::RpcCall)?
            .into_inner();
        ensure!(
            response.transactions.len() == digests.len(),
            Error::MalformedResponse
        );

        response
            .transactions
            .into_iter()
            .filter_map(|result| finalized_transaction(result).transpose())
            .map(|transaction| transaction.map(|transaction| (transaction.digest, transaction)))
            .collect()
    }
}

#[async_trait]
impl SuiClient for Client {
    async fn finalized_transaction_blocks(
        &self,
        digests: HashSet<Digest>,
    ) -> Result<HashMap<Digest, Transaction>> {
        let digests: Vec<_> = digests.into_iter().collect();
        let batches: Vec<_> = digests
            .chunks(BATCH_SIZE)
            .map(|batch| self.fetch(batch))
            .collect();

        Ok(stream::iter(batches)
            .buffer_unordered(MAX_CONCURRENT_REQUESTS)
            .try_concat()
            .await?
            .into_iter()
            .collect())
    }
}

fn too_large(err: &Report<Error>) -> bool {
    err.downcast_ref::<tonic::Status>()
        .is_some_and(|status| status.code() == Code::OutOfRange)
}

fn headers_interceptor(headers: HashMap<String, String>) -> Result<HeadersInterceptor> {
    let mut interceptor = HeadersInterceptor::new();

    for (name, value) in headers {
        let key = MetadataKey::<Ascii>::from_bytes(name.as_bytes())
            .change_context(Error::Header)
            .attach_printable_lazy(|| name.clone())?;
        let mut value = MetadataValue::try_from(value)
            .change_context(Error::Header)
            .attach_printable_lazy(|| name.clone())?;
        // Header values carry provider credentials: keep them out of debug output
        // and of the HTTP/2 header compression table.
        value.set_sensitive(true);
        interceptor.headers_mut().insert(key, value);
    }

    Ok(interceptor)
}

// The digest to key the response, the checkpoint to determine finality and the event
// fields [`Transaction`] is built from.
fn read_mask() -> FieldMask {
    let event = || ExecutedTransaction::path_builder().events().events();
    FieldMask::from_paths([
        ExecutedTransaction::path_builder().digest(),
        ExecutedTransaction::path_builder().checkpoint(),
        event().package_id(),
        event().module(),
        event().sender(),
        event().event_type(),
        event().contents().finish(),
    ])
}

// A transaction the node does not know is reported as a per-digest `NOT_FOUND` and left
// out, so that it is voted as not found. Any other per-digest failure fails the call, so
// that the poll is retried instead of voted on.
fn finalized_transaction(result: GetTransactionResult) -> Result<Option<Transaction>> {
    let transaction = match result.result {
        Some(Lookup::Transaction(transaction)) => transaction,
        Some(Lookup::Error(status)) if status.code == i32::from(Code::NotFound) => return Ok(None),
        Some(Lookup::Error(status)) => {
            return Err(report!(Error::RpcCall).attach_printable(format!(
                "{:?}: {}",
                Code::from(status.code),
                status.message
            )));
        }
        _ => return Err(report!(Error::MalformedResponse)),
    };

    // Checkpoint number exists when this transaction was included and finalized.
    transaction
        .checkpoint
        .map(|_| Transaction::try_from(transaction))
        .transpose()
        .change_context(Error::MalformedResponse)
}

#[cfg(test)]
mod tests {
    use ampd::monitoring::test_utils;
    use bytes::Bytes;
    use prost::Message as _;
    use sui_rpc::proto::google::rpc::Status;
    use sui_rpc::proto::sui::rpc::v2::BatchGetTransactionsResponse;
    use tokio::sync::mpsc;

    use super::*;

    fn status(code: Code) -> Status {
        Status::default().with_code(i32::from(code))
    }

    fn finalized(digest: Digest) -> ExecutedTransaction {
        ExecutedTransaction::default()
            .with_digest(digest.to_string())
            .with_checkpoint(1)
    }

    enum Reply {
        /// Headers at once, then nothing: only a whole-call deadline ends it.
        StalledBody,
        /// A message declared larger than the receive limit.
        TooLarge,
        /// One `NOT_FOUND` result, as for a single unknown digest.
        NotFound,
        /// A response with no results at all.
        Empty,
    }

    /// A gRPC frame: a compression flag and a big-endian length, then the message.
    fn frame(message: &[u8]) -> Bytes {
        let mut frame = vec![0];
        frame.extend(u32::try_from(message.len()).unwrap().to_be_bytes());
        frame.extend(message);
        frame.into()
    }

    /// A bare HTTP/2 server answering requests in order with `replies`, then with `NotFound`.
    async fn mock_server(replies: Vec<Reply>) -> Url {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(socket).await.unwrap();
            let mut replies = replies.into_iter();
            while let Some(Ok((_, mut respond))) = connection.accept().await {
                let reply = replies.next().unwrap_or(Reply::NotFound);
                tokio::spawn(async move {
                    let response = http::Response::builder()
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap();
                    let mut stream = respond.send_response(response, false).unwrap();
                    let frame = match reply {
                        Reply::StalledBody => std::future::pending().await,
                        Reply::TooLarge => Bytes::from_static(&[0, 0x20, 0, 0, 0]),
                        Reply::NotFound => frame(
                            &BatchGetTransactionsResponse::new(vec![
                                GetTransactionResult::new_error(status(Code::NotFound)),
                            ])
                            .encode_to_vec(),
                        ),
                        Reply::Empty => frame(&[]),
                    };
                    stream.send_data(frame, false).unwrap();
                    let mut trailers = http::HeaderMap::new();
                    trailers.insert("grpc-status", "0".parse().unwrap());
                    stream.send_trailers(trailers).unwrap();
                });
            }
        });
        Url::new_non_sensitive(&url).unwrap()
    }

    fn client(url: &Url, timeout: Duration) -> (Client, mpsc::Receiver<Msg>) {
        let (monitoring_client, receiver) = test_utils::monitoring_client();
        let client = Client::new(
            url,
            timeout,
            HashMap::new(),
            monitoring_client,
            "sui".parse().unwrap(),
        )
        .unwrap();
        (client, receiver)
    }

    #[test]
    fn should_skip_transaction_not_found() {
        let result = GetTransactionResult::new_error(status(Code::NotFound));

        assert_eq!(finalized_transaction(result).unwrap(), None);
    }

    #[test]
    fn should_fail_on_other_transaction_errors() {
        let result = GetTransactionResult::new_error(status(Code::Internal));

        let err = finalized_transaction(result).unwrap_err();
        assert!(matches!(err.current_context(), Error::RpcCall));
    }

    #[test]
    fn should_skip_transaction_not_in_checkpoint() {
        let transaction = ExecutedTransaction::default()
            .with_digest(Digest::generate(rand::thread_rng()).to_string());
        let result = GetTransactionResult::new_transaction(transaction);

        assert_eq!(finalized_transaction(result).unwrap(), None);
    }

    #[test]
    fn should_convert_finalized_transaction() {
        let digest = Digest::generate(rand::thread_rng());
        let result = GetTransactionResult::new_transaction(finalized(digest));

        assert_eq!(
            finalized_transaction(result).unwrap(),
            Some(Transaction {
                digest,
                events: vec![],
            })
        );
    }

    #[test]
    fn should_fail_on_malformed_result() {
        let invalid_digest = ExecutedTransaction::default()
            .with_digest("not a digest")
            .with_checkpoint(1);

        for result in [
            GetTransactionResult::new_transaction(invalid_digest),
            GetTransactionResult::default(),
        ] {
            let err = finalized_transaction(result).unwrap_err();
            assert!(matches!(err.current_context(), Error::MalformedResponse));
        }
    }

    #[test]
    fn should_set_sensitive_headers() {
        let headers = HashMap::from([("x-token".to_string(), "secret".to_string())]);

        let interceptor = headers_interceptor(headers).unwrap();

        let value = interceptor.headers().get("x-token").unwrap();
        assert_eq!(value.to_str().unwrap(), "secret");
        assert!(value.is_sensitive());
    }

    #[test]
    fn should_reject_invalid_header() {
        let headers = HashMap::from([("invalid header".to_string(), "secret".to_string())]);

        assert!(headers_interceptor(headers).is_err());
    }

    #[tokio::test]
    async fn should_fail_when_the_body_exceeds_the_timeout() {
        let url = mock_server(vec![Reply::StalledBody]).await;
        let (client, mut receiver) = client(&url, Duration::from_millis(200));
        let started = std::time::Instant::now();

        let result = client
            .finalized_transaction_blocks(HashSet::from([Digest::generate(rand::thread_rng())]))
            .await;

        assert!(matches!(
            result.unwrap_err().current_context(),
            Error::RpcCall
        ));
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(matches!(
            receiver.recv().await.unwrap(),
            Msg::RpcCall { success: false, .. }
        ));
    }

    #[tokio::test]
    async fn should_fail_on_a_response_with_fewer_results_than_digests() {
        let url = mock_server(vec![Reply::Empty]).await;
        let (client, _) = client(&url, Duration::from_secs(5));

        let result = client
            .finalized_transaction_blocks(HashSet::from([Digest::generate(rand::thread_rng())]))
            .await;

        assert!(matches!(
            result.unwrap_err().current_context(),
            Error::MalformedResponse
        ));
    }

    #[tokio::test]
    async fn should_refetch_one_at_a_time_when_the_response_is_too_large() {
        let url = mock_server(vec![Reply::TooLarge]).await;
        let (client, mut receiver) = client(&url, Duration::from_secs(5));
        let digests = HashSet::from([
            Digest::generate(rand::thread_rng()),
            Digest::generate(rand::thread_rng()),
        ]);

        let transactions = client.finalized_transaction_blocks(digests).await.unwrap();

        assert!(transactions.is_empty());
        let mut outcomes = Vec::new();
        for _ in 0..3 {
            if let Msg::RpcCall { success, .. } = receiver.recv().await.unwrap() {
                outcomes.push(success);
            }
        }
        outcomes.sort_unstable();
        assert_eq!(outcomes, [false, true, true]);
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn should_fetch_in_batches_and_record_each_failure() {
        let url = Url::new_non_sensitive("http://invalid_link").unwrap();
        let (client, mut receiver) = client(&url, Duration::from_secs(1));
        let digests = (0..=BATCH_SIZE)
            .map(|_| Digest::generate(rand::thread_rng()))
            .collect();

        let result = client.finalized_transaction_blocks(digests).await;

        assert!(matches!(
            result.unwrap_err().current_context(),
            Error::RpcCall
        ));
        assert!(matches!(
            receiver.recv().await.unwrap(),
            Msg::RpcCall { success: false, .. }
        ));
    }
}
