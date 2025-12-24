use ampd::types::{EVMAddress, Hash};
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
use multisig::verifier_set::VerifierSet;
use serde::Deserialize;

#[derive(Clone, Deserialize, Debug)]
pub struct Message {
    pub message_id: HexTxHashAndEventIndex,
    pub destination_address: String,
    pub destination_chain: ChainName,
    pub source_address: EVMAddress,
    pub payload_hash: Hash,
}

#[derive(Clone, Debug, Deserialize)]
pub struct VerifierSetConfirmation {
    pub message_id: HexTxHashAndEventIndex,
    pub verifier_set: VerifierSet,
}
