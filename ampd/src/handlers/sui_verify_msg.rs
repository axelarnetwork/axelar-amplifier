use serde::Deserialize;
use sui_types::base_types::{SuiAddress, TransactionDigest};

use crate::types::Hash;

#[derive(Deserialize)]
pub struct Message {
    pub tx_id: TransactionDigest,
    pub event_index: u64,
    pub destination_address: String,
    pub destination_chain: connection_router::state::ChainName,
    pub source_address: SuiAddress,
    pub payload_hash: Hash,
}
