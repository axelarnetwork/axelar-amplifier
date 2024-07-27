use axelar_wasm_std::hash::Hash;
use axelar_wasm_std::MajorityThreshold;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};
use multisig::key::KeyType;
use multisig::verifier_set::VerifierSet;
use router_api::ChainName;

use crate::encoding::Encoder;
use crate::payload::{Payload, PayloadId};

#[cw_serde]
pub struct Config {
    pub gateway: Addr,
    pub multisig: Addr,
    pub coordinator: Addr,
    pub service_registry: Addr,
    pub voting_verifier: Addr,
    pub signing_threshold: MajorityThreshold,
    pub service_name: String,
    pub chain_name: ChainName,
    pub verifier_set_diff_threshold: u32,
    pub encoder: Encoder,
    pub key_type: KeyType,
    pub domain_separator: Hash,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const PAYLOAD: Map<&PayloadId, Payload> = Map::new("payload");
pub const MULTISIG_SESSION_PAYLOAD: Map<u64, PayloadId> = Map::new("multisig_session_payload");

pub const REPLY_TRACKER: Item<PayloadId> = Item::new("reply_tracker");

pub const CURRENT_VERIFIER_SET: Item<VerifierSet> = Item::new("current_verifier_set");
pub const NEXT_VERIFIER_SET: Item<VerifierSet> = Item::new("next_verifier_set");
