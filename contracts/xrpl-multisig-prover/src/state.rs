use std::ops::{Add, Sub};

use axelar_wasm_std::MajorityThreshold;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint256};
use cw_storage_plus::{Item, Map};
use interchain_token_service::TokenId;
use router_api::{ChainName, ChainNameRaw, CrossChainId};
use xrpl_types::types::{
    TxHash, XRPLAccountId, XRPLPaymentAmount, XRPLToken, XRPLTxStatus, XRPLUnsignedTx,
};

use crate::axelar_verifiers::VerifierSet;
use crate::error::ContractError;

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
    pub xrpl_fee: u64,
    pub ticket_count_threshold: u32,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const REPLY_UNSIGNED_TX_HASH: Item<TxHash> = Item::new("reply_unsigned_tx_hash");
pub const REPLY_CROSS_CHAIN_ID: Item<CrossChainId> = Item::new("reply_cross_chain_id");

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

pub const MULTISIG_SESSION_ID_TO_UNSIGNED_TX_HASH: Map<u64, TxHash> =
    Map::new("multisig_session_id_to_unsigned_tx_hash");
pub const CROSS_CHAIN_ID_TO_TICKET: Map<&CrossChainId, u32> = Map::new("cross_chain_id_to_ticket");
pub const CROSS_CHAIN_ID_TO_MULTISIG_SESSION: Map<&CrossChainId, MultisigSession> =
    Map::new("cross_chain_id_to_multisig_session");
pub const CONSUMED_TICKET_TO_UNSIGNED_TX_HASH: Map<&u32, TxHash> =
    Map::new("consumed_ticket_to_unsigned_tx_hash");
pub const UNSIGNED_TX_HASH_TO_TX_INFO: Map<&TxHash, TxInfo> =
    Map::new("unsigned_tx_hash_to_tx_info");
pub const LATEST_SEQUENTIAL_UNSIGNED_TX_HASH: Item<TxHash> =
    Item::new("latest_sequential_unsigned_tx_hash");
pub const TRUST_LINE: Map<&XRPLToken, ()> = Map::new("trust_line");

#[cw_serde]
pub enum DustAmount {
    Local(XRPLPaymentAmount),
    Remote(Uint256),
}

impl std::fmt::Display for DustAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DustAmount::Local(amount) => write!(f, "{}", amount),
            DustAmount::Remote(amount) => write!(f, "{}", amount),
        }
    }
}

impl DustAmount {
    pub fn is_zero(&self) -> bool {
        match self {
            DustAmount::Local(amount) => amount.is_zero(),
            DustAmount::Remote(amount) => amount.is_zero(),
        }
    }

    pub fn add(self, other: Self) -> Result<Self, ContractError> {
        match (self, other) {
            (DustAmount::Local(a), DustAmount::Local(b)) => Ok(DustAmount::Local(a.add(b)?)),
            (DustAmount::Remote(a), DustAmount::Remote(b)) => Ok(DustAmount::Remote(
                a.checked_add(b).map_err(|_| ContractError::Overflow)?,
            )),
            _ => panic!("cannot add local and remote dust amounts"),
        }
    }

    pub fn sub(self, other: Self) -> Result<Self, ContractError> {
        match (self, other) {
            (DustAmount::Local(a), DustAmount::Local(b)) => Ok(DustAmount::Local(a.sub(b)?)),
            (DustAmount::Remote(a), DustAmount::Remote(b)) => Ok(DustAmount::Remote(
                a.checked_sub(b).map_err(|_| ContractError::Overflow)?,
            )),
            _ => panic!("cannot subtract local and remote dust amounts"),
        }
    }

    pub fn unwrap_local(self) -> Result<XRPLPaymentAmount, ContractError> {
        match self {
            DustAmount::Local(amount) => Ok(amount),
            _ => Err(ContractError::DustAmountNotLocal),
        }
    }

    pub fn unwrap_remote(self) -> Result<Uint256, ContractError> {
        match self {
            DustAmount::Remote(amount) => Ok(amount),
            _ => Err(ContractError::DustAmountNotRemote),
        }
    }
}

#[cw_serde]
pub struct DustInfo {
    pub token_id: TokenId,
    pub chain: ChainNameRaw,
    pub dust_amount: DustAmount,
}

pub const DUST: Map<&(TokenId, ChainNameRaw), DustAmount> = Map::new("dust");
pub const UNSIGNED_TX_HASH_TO_DUST_INFO: Map<&TxHash, DustInfo> =
    Map::new("unsigned_tx_hash_to_dust_info");
pub const DUST_COUNTED: Map<&CrossChainId, ()> = Map::new("dust_counted");

pub const CURRENT_VERIFIER_SET: Item<VerifierSet> = Item::new("current_verifier_set");
pub const NEXT_VERIFIER_SET: Item<VerifierSet> = Item::new("next_verifier_set");
