use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::str::FromStr;

use error_stack::{report, Result};
use futures::future::join_all;
use num_traits::cast;
use serde::de::Error as DeserializeError;
use serde::{Deserialize, Deserializer, Serialize};
use stellar_rs::horizon_client::HorizonClient;
use stellar_rs::transactions::prelude::{SingleTransactionRequest, TransactionResponse};
use stellar_xdr::curr::{ContractEvent, Limits, ReadXdr, ScAddress, TransactionMeta, VecM};
use thiserror::Error;
use tracing::warn;

#[cfg(test)]
use crate::types::Hash;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to create client")]
    Client,
    #[error("invalid tx hash")]
    TxHash,
    #[error("failed to deserialize tx id")]
    FailedTxIdDeserialization,
}

/// StellarTxId is a wrapper around a Stellar transaction hash.
/// The hash is encoded as a hex string and not 0x prefixed as required by the Stellar RPC.
#[derive(Debug, Clone, Eq, Hash, Deserialize, Serialize, PartialEq)]
pub struct StellarTxId(#[serde(deserialize_with = "deserialize_stellar_tx_id")] String);

/// Deserializes a Stellar tx id from a 0x-prefixed tx id.
fn deserialize_stellar_tx_id<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let tx_id: String = String::deserialize(deserializer)?;
    tx_id
        .strip_prefix("0x")
        .map(String::from)
        .ok_or(D::Error::custom(Error::FailedTxIdDeserialization))
}

impl StellarTxId {
    pub fn to_message_id(&self, event_index: u32) -> String {
        format!("0x{}-{}", self.0.clone(), event_index)
    }

    #[cfg(test)]
    pub fn from_hash(hash: Hash) -> Self {
        StellarTxId(format!("{:x}", hash))
    }
}

impl Display for StellarTxId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.clone())
    }
}

/// TxResponse parses XDR encoded TransactionMeta to ContractEvent type, and only contains necessary fields for verification
#[derive(Debug)]
pub struct TxResponse {
    pub transaction_hash: StellarTxId,
    pub source_address: ScAddress,
    pub successful: bool,
    pub contract_events: Option<VecM<ContractEvent>>,
}

impl From<TransactionResponse> for TxResponse {
    fn from(response: TransactionResponse) -> Self {
        let events =
            match TransactionMeta::from_xdr_base64(response.result_meta_xdr(), Limits::none()) {
                Ok(TransactionMeta::V3(data)) => match data.soroban_meta {
                    Some(meta) => meta.events,
                    None => VecM::default(),
                },
                _ => VecM::default(),
            };

        Self {
            transaction_hash: StellarTxId(response.id().to_owned()),
            successful: *response.successful(),
            source_address: ScAddress::from_str(response.source_account())
                .expect("must convert to Stellar address"),
            contract_events: Some(events),
        }
    }
}

impl TxResponse {
    pub fn has_failed(&self) -> bool {
        !self.successful
    }

    pub fn event(&self, index: u32) -> Option<&ContractEvent> {
        match self.contract_events {
            Some(ref events) => {
                let log_index: usize = cast(index).expect("event index must be a valid usize");
                events.get(log_index)
            }
            None => None,
        }
    }

    pub fn tx_hash(&self) -> String {
        self.transaction_hash.clone().to_string()
    }
}

#[cfg_attr(test, faux::create)]
pub struct Client(HorizonClient);

#[cfg_attr(test, faux::methods)]
impl Client {
    pub fn new(url: String) -> Result<Self, Error> {
        Ok(Self(HorizonClient::new(url).map_err(|err_str| {
            report!(Error::Client).attach_printable(err_str)
        })?))
    }

    pub async fn transaction_responses(
        &self,
        tx_hashes: HashSet<String>,
    ) -> Result<HashMap<String, TxResponse>, Error> {
        let tx_hashes: Vec<_> = tx_hashes
            .into_iter()
            .map(|tx_hash| {
                SingleTransactionRequest::new()
                    .set_transaction_hash(tx_hash)
                    .map_err(|err_str| report!(Error::TxHash).attach_printable(err_str))
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(join_all(
            tx_hashes
                .iter()
                .map(|tx_hash| self.0.get_single_transaction(tx_hash)),
        )
        .await
        .into_iter()
        .map(|tx_response| tx_response.map(TxResponse::from))
        .filter_map(|tx_response| match tx_response {
            Ok(tx_response) => Some((tx_response.tx_hash(), tx_response)),
            Err(err) => {
                warn!(err, "failed to get transaction response");
                None
            }
        })
        .collect::<HashMap<_, _>>())
    }

    pub async fn transaction_response(&self, tx_hash: String) -> Result<Option<TxResponse>, Error> {
        let tx_hash = SingleTransactionRequest::new()
            .set_transaction_hash(tx_hash)
            .map_err(|err_str| report!(Error::TxHash).attach_printable(err_str))?;

        Ok(self
            .0
            .get_single_transaction(&tx_hash)
            .await
            .map(|tx_response| Some(tx_response.into()))
            .unwrap_or_else(|err| {
                warn!(err, "failed to get transaction response");
                None
            }))
    }
}
