use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use error_stack::{report, ResultExt};
use futures::future::join_all;
use stellar_rpc_client::GetTransactionResponse;
use stellar_xdr::curr::{ContractEvent, Hash, VecM};
use thiserror::Error;
use tracing::warn;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to create client")]
    Client,
    #[error("invalid tx hash")]
    TxHash,
}

/// TxResponse parses XDR encoded TransactionMeta to ContractEvent type, and only contains necessary fields for verification
#[derive(Debug)]
pub struct TxResponse {
    pub transaction_hash: String,
    pub successful: bool,
    pub contract_events: VecM<ContractEvent>,
}

const STATUS_SUCCESS: &str = "SUCCESS";

impl From<(Hash, GetTransactionResponse)> for TxResponse {
    fn from((transaction_hash, response): (Hash, GetTransactionResponse)) -> Self {
        // Protocol 23 (CAP-0067): Extract contract events from the unified events structure
        // contract_events is Vec<Vec<ContractEvent>> (per operation), so we flatten it
        let mut events_vec = response
            .events
            .contract_events
            .into_iter()
            .flatten()
            .collect::<Vec<ContractEvent>>();

        let event_count = events_vec.len();
        let contract_events = match events_vec.clone().try_into() {
            Ok(vec_m) => vec_m,
            Err(_) => {
                // VecM has a maximum capacity (typically 4294967295 elements for XDR)
                // but we need to find the actual limit by binary search or use a reasonable limit
                const MAX_EVENTS: usize = 1000; // Conservative limit to prevent memory issues

                if events_vec.len() > MAX_EVENTS {
                    events_vec.truncate(MAX_EVENTS);
                    warn!(
                        tx_hash = %transaction_hash,
                        original_count = event_count,
                        truncated_count = events_vec.len(),
                        "Contract events exceed VecM capacity, truncating to {} events",
                        MAX_EVENTS
                    );
                } else {
                    // If it's not a size issue, try progressively smaller sizes
                    let mut max_size = events_vec.len();
                    while max_size > 0 {
                        max_size /= 2;
                        events_vec.truncate(max_size);
                        if let Ok(vec_m) = events_vec.clone().try_into() {
                            warn!(
                                tx_hash = %transaction_hash,
                                original_count = event_count,
                                truncated_count = events_vec.len(),
                                "Contract events exceed VecM capacity, truncated to {} events",
                                events_vec.len()
                            );
                            return Self {
                                transaction_hash: transaction_hash.to_string(),
                                successful: response.status == STATUS_SUCCESS,
                                contract_events: vec_m,
                            };
                        }
                    }

                    warn!(
                        tx_hash = %transaction_hash,
                        event_count,
                        "Failed to fit any contract events in VecM, returning empty list"
                    );
                }

                events_vec.try_into().unwrap_or_else(|_| VecM::default())
            }
        };

        Self {
            transaction_hash: transaction_hash.to_string(),
            successful: response.status == STATUS_SUCCESS,
            contract_events,
        }
    }
}

impl TxResponse {
    pub fn has_failed(&self) -> bool {
        !self.successful
    }

    pub fn event(&self, index: u64) -> Option<&ContractEvent> {
        let log_index = usize::try_from(index).ok()?;
        self.contract_events.get(log_index)
    }

    pub fn tx_hash(&self) -> String {
        self.transaction_hash.clone()
    }
}

#[cfg_attr(test, faux::create)]
#[derive(Debug)]
pub struct Client(stellar_rpc_client::Client);

#[cfg_attr(test, faux::methods)]
impl Client {
    pub fn new(url: String) -> error_stack::Result<Self, Error> {
        Ok(Self(
            stellar_rpc_client::Client::new(url.as_str())
                .map_err(|err_str| report!(Error::Client).attach_printable(err_str))?,
        ))
    }

    pub async fn transaction_responses(
        &self,
        tx_hashes: HashSet<String>,
    ) -> error_stack::Result<HashMap<String, TxResponse>, Error> {
        let tx_hashes: Vec<_> = tx_hashes
            .into_iter()
            .map(|tx_hash| Hash::from_str(tx_hash.as_str()).change_context(Error::TxHash))
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let responses = join_all(
            tx_hashes
                .iter()
                .map(|tx_hash| self.0.get_transaction(tx_hash)),
        )
        .await;

        Ok(responses
            .into_iter()
            .zip(tx_hashes)
            .filter_map(|(response, hash)| match response {
                Ok(resp) => {
                    let tx_response = TxResponse::from((hash, resp));
                    Some((tx_response.tx_hash(), tx_response))
                }
                Err(err) => {
                    warn!(error = ?err, tx_hash = ?hash, "failed to get transaction response");
                    None
                }
            })
            .collect::<HashMap<_, _>>())
    }

    pub async fn transaction_response(
        &self,
        tx_hash: String,
    ) -> error_stack::Result<Option<TxResponse>, Error> {
        let tx_hash = Hash::from_str(tx_hash.as_str()).change_context(Error::TxHash)?;

        match self.0.get_transaction(&tx_hash).await {
            Ok(response) => Ok(Some(TxResponse::from((tx_hash, response)))),
            Err(err) => {
                warn!(error = ?err, "failed to get transaction response");
                Ok(None)
            }
        }
    }
}
