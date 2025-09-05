use axelar_wasm_std::MajorityThreshold;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, HexBinary, Storage};
use cw_storage_plus::{Item, Map};
use multisig::key::KeyType;
use multisig::verifier_set::VerifierSet;
use multisig_prover_api::payload::{Payload, PayloadId};
use router_api::ChainName;

use crate::error::ContractError;

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
    #[serde(default)]
    pub sig_verifier_address: Option<Addr>,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const PAYLOAD: Map<&PayloadId, Payload> = Map::new("payload");
pub const MULTISIG_SESSION_PAYLOAD: Map<u64, PayloadId> = Map::new("multisig_session_payload");

// we only need to save full message payloads if both the `notify-signing-session` and `receive-payload`
// features are enabled
#[cfg(all(feature = "notify-signing-session", feature = "receive-payload"))]
pub const FULL_MESSAGE_PAYLOADS: FullPayloadStorage =
    FullPayloadStorage::Save(Map::new("full_message_payloads"));
#[cfg(not(all(feature = "notify-signing-session", feature = "receive-payload")))]
pub const FULL_MESSAGE_PAYLOADS: FullPayloadStorage = FullPayloadStorage::Ignore;

pub const REPLY_TRACKER: Item<PayloadId> = Item::new("reply_tracker");

pub const CURRENT_VERIFIER_SET: Item<VerifierSet> = Item::new("current_verifier_set");
pub const NEXT_VERIFIER_SET: Item<VerifierSet> = Item::new("next_verifier_set");

#[allow(dead_code)] // variants are only used when the relevant features are enabled
pub enum FullPayloadStorage<'a> {
    Ignore,
    Save(Map<&'a PayloadId, Vec<cosmwasm_std::HexBinary>>),
}

impl<'a> FullPayloadStorage<'a> {
    pub fn save(
        &self,
        storage: &'a mut dyn Storage,
        payload_id: &PayloadId,
        full_message_payloads: &Vec<HexBinary>,
    ) -> Result<(), ContractError> {
        match self {
            FullPayloadStorage::Ignore => Ok(()),
            FullPayloadStorage::Save(map) => map
                .save(storage, payload_id, full_message_payloads)
                .map_err(ContractError::from),
        }
    }

    #[allow(dead_code)] // only used when the `notify-signing-session` feature is enabled
    pub fn may_load(
        &self,
        storage: &'a dyn Storage,
        payload_id: &PayloadId,
    ) -> Result<Option<Vec<HexBinary>>, ContractError> {
        match self {
            FullPayloadStorage::Ignore => Ok(None),
            FullPayloadStorage::Save(map) => map
                .may_load(storage, payload_id)
                .map_err(ContractError::from),
        }
    }
}
