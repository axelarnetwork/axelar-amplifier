use axelar_wasm_std::hash::Hash;
use axelar_wasm_std::MajorityThreshold;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, HexBinary};
use cw_storage_plus::{Item, Map};
use multisig::key::KeyType;
use multisig::verifier_set::VerifierSet;
use router_api::ChainName;
use solana_multisig_prover_api::payload::{Payload, PayloadId};

#[cw_serde]
pub struct Config {
    pub gateway: Addr,
    pub multisig: Addr,
    pub coordinator: Addr,
    pub service_registry: Addr,
    pub voting_verifier: Addr,
    pub chain_codec: Addr,
    pub signing_threshold: MajorityThreshold,
    pub service_name: String,
    pub chain_name: ChainName,
    pub verifier_set_diff_threshold: u32,
    pub key_type: KeyType,
    pub domain_separator: Hash,
    pub notify_signing_session: bool,
    pub expect_full_message_payloads: bool,
    #[serde(default)]
    pub sig_verifier_address: Option<Addr>,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const PAYLOAD: Map<&PayloadId, Payload> = Map::new("payload");
pub const MULTISIG_SESSION_PAYLOAD: Map<u64, PayloadId> = Map::new("multisig_session_payload");

// we only need to save full message payloads if both the `notify-signing-session` and `receive-payload`
// features are enabled
pub const FULL_MESSAGE_PAYLOADS: Map<&PayloadId, Vec<HexBinary>> =
    Map::new("full_message_payloads");

pub const REPLY_TRACKER: Item<PayloadId> = Item::new("reply_tracker");

pub const CURRENT_VERIFIER_SET: Item<VerifierSet> = Item::new("current_verifier_set");
pub const NEXT_VERIFIER_SET: Item<VerifierSet> = Item::new("next_verifier_set");
