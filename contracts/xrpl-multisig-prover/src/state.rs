use axelar_wasm_std::hash::Hash;
use axelar_wasm_std::msg_id::HexTxHash;
use axelar_wasm_std::MajorityThreshold;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};
use router_api::{ChainName, CrossChainId};
use xrpl_types::types::{XRPLAccountId, XRPLToken, XRPLTxStatus, XRPLUnsignedTx};

use crate::axelar_verifiers::VerifierSet;

#[cw_serde]
pub struct Config {
    pub multisig: Addr,
    pub coordinator: Addr,
    pub gateway: Addr,
    pub signing_threshold: MajorityThreshold,
    pub xrpl_multisig: XRPLAccountId,
    pub voting_verifier: Addr,
    pub service_registry: Addr,
    pub service_name: String,
    pub chain_name: ChainName,
    pub verifier_set_diff_threshold: u32,
    pub xrpl_transaction_fee: u64,
    pub xrpl_base_reserve: u64,
    pub xrpl_owner_reserve: u64,
    pub ticket_count_threshold: u32,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const REPLY_UNSIGNED_TX_HASH: Item<HexTxHash> = Item::new("reply_unsigned_tx_hash");

// The next seq. no. is affected by the number of tickets created,
// not solely on the last sequence number used.
// On the contrary, the next ticket number to be used cannot be determined before proof construction,
// as it depends on the tickets available at the time.
// After all ticket numbers are used, we reuse the smallest available ticket number,
// going over all ticket numbers again, wrapping around.
pub const NEXT_SEQUENCE_NUMBER: Item<u32> = Item::new("next_sequence_number");
pub const LAST_ASSIGNED_TICKET_NUMBER: Item<u32> = Item::new("last_assigned_ticket_number");
pub const AVAILABLE_TICKETS: Item<Vec<u32>> = Item::new("available_tickets");

#[cw_serde]
pub struct MultisigSession {
    // TODO: rename
    pub id: u64,
    pub expires_at: u64,
}

#[cw_serde]
pub struct TxInfo {
    pub status: XRPLTxStatus,
    pub unsigned_tx: XRPLUnsignedTx,
    pub original_cc_id: Option<CrossChainId>,
}

pub const MULTISIG_SESSION_ID_TO_UNSIGNED_TX_HASH: Map<u64, Hash> =
    Map::new("multisig_session_id_to_unsigned_tx_hash");
pub const CROSS_CHAIN_ID_TO_TICKET: Map<&CrossChainId, u32> = Map::new("cross_chain_id_to_ticket");
pub const CROSS_CHAIN_ID_TO_MULTISIG_SESSION: Map<&CrossChainId, MultisigSession> =
    Map::new("cross_chain_id_to_multisig_session");
pub const CONSUMED_TICKET_TO_UNSIGNED_TX_HASH: Map<&u32, Hash> =
    Map::new("consumed_ticket_to_unsigned_tx_hash");
pub const UNSIGNED_TX_HASH_TO_TX_INFO: Map<&Hash, TxInfo> = Map::new("unsigned_tx_hash_to_tx_info");
pub const LATEST_SEQUENTIAL_UNSIGNED_TX_HASH: Item<Hash> =
    Item::new("latest_sequential_unsigned_tx_hash");
pub const TRUST_LINE: Map<&XRPLToken, ()> = Map::new("trust_line");
pub const TRUST_LINE_COUNT: Item<u64> = Item::new("trust_line_count");
pub const SEQUENCE_NUMBER_MAX_OBJECT_COUNT: Map<&u32, u8> = Map::new("sequence_number_max_object_count");

pub const FEE_RESERVE: Item<u64> = Item::new("fee_reserve");
pub const FEE_RESERVE_TOP_UP_COUNTED: Map<&Hash, ()> = Map::new("fee_reserve_top_up_counted");

pub const CURRENT_VERIFIER_SET: Item<VerifierSet> = Item::new("current_verifier_set");
pub const NEXT_VERIFIER_SET: Item<VerifierSet> = Item::new("next_verifier_set");
