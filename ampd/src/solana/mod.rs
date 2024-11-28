use std::str::FromStr;

use futures::FutureExt;
use serde::Deserializer;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{pubkey::Pubkey, signature::Signature};
use solana_transaction_status::UiTransactionStatusMeta;

pub mod msg_verifier;
pub mod verifier_set_verifier;

pub async fn fetch_message(
    rpc_client: &RpcClient,
    signature: Signature,
) -> Option<(Signature, UiTransactionStatusMeta)> {
    rpc_client
        .get_transaction(
            &signature,
            solana_transaction_status::UiTransactionEncoding::Base58,
        )
        .map(|tx_data_result| {
            tx_data_result
                .map(|tx_data| tx_data.transaction.meta)
                .ok()
                .flatten()
                .map(|tx_data| (signature, tx_data))
        })
        .await
}

pub fn deserialize_pubkey<'de, D>(deserializer: D) -> Result<Pubkey, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Pubkey::from_str(&s).map_err(serde::de::Error::custom)
}
