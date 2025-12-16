use ampd::types::Hash;
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::msg_id::Base58TxDigestAndEventIndex;
use multisig::verifier_set::VerifierSet;
use serde::Deserialize;
use sui_types::base_types::SuiAddress;

#[derive(Clone, Deserialize, Debug)]
pub struct Message {
    pub message_id: Base58TxDigestAndEventIndex,
    pub destination_address: String,
    pub destination_chain: ChainName,
    pub source_address: SuiAddress,
    pub payload_hash: Hash,
}

#[derive(Clone, Deserialize, Debug)]
pub struct VerifierSetConfirmation {
    pub message_id: Base58TxDigestAndEventIndex,
    pub verifier_set: VerifierSet,
}
