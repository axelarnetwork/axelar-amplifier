use axelar_wasm_std::Threshold;
use connection_router::state::CrossChainId;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};
use cosmwasm_schema::cw_serde;
use crate::{types::{TransactionInfo, TxHash, XRPLToken}, axelar_workers::WorkerSet};

#[cw_serde]
pub struct Config {
    pub axelar_multisig_address: Addr,
    pub gateway_address: Addr,
    pub signing_threshold: Threshold,
    pub xrpl_multisig_address: String,
    pub voting_verifier_address: Addr,
    pub service_registry_address: Addr,
    pub service_name: String,
    pub worker_set_diff_threshold: u32,
    pub xrpl_fee: u64,
    pub ticket_count_threshold: u32,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const REPLY_TX_HASH: Item<TxHash> = Item::new("reply_tx_hash");
pub const MULTISIG_SESSION_TX: Map<u64, TxHash> = Map::new("multisig_session_tx");

// The next seq. no. is determined on TicketCreate and depends on the number of created tickets,
// not solely on the last sequence number used.
// On the contrary, the next ticket number to be used cannot be determined before proof construction,
// as it depends on the tickets available at the time.
// After all ticket numbers are used, we reuse the smallest available ticket number,
// going over all ticket numbers again, wrapping around.
pub const NEXT_SEQUENCE_NUMBER: Item<u32> = Item::new("next_sequence_number");
pub const LAST_ASSIGNED_TICKET_NUMBER: Item<u32> = Item::new("last_assigned_ticket_number");

pub const SIGNED_TO_UNSIGNED_TX_HASH: Map<TxHash, TxHash> = Map::new("signed_to_unsigned_tx_hash");
pub const MESSAGE_ID_TO_TICKET: Map<CrossChainId, u32> = Map::new("message_id_to_ticket");
pub const CONFIRMED_TRANSACTIONS: Map<u32, TxHash> = Map::new("confirmed_transactions");
pub const AVAILABLE_TICKETS: Item<Vec<u32>> = Item::new("available_tickets");
pub const TRANSACTION_INFO: Map<TxHash, TransactionInfo> = Map::new("transaction_info");
pub const LATEST_SEQUENTIAL_TX_HASH: Item<TxHash> = Item::new("latest_sequential_tx_hash");

pub const TOKENS: Map<String, XRPLToken> = Map::new("tokens");

pub const CURRENT_WORKER_SET: Item<WorkerSet> = Item::new("current_worker_set");
pub const NEXT_WORKER_SET: Map<TxHash, WorkerSet> = Map::new("next_worker_set");
