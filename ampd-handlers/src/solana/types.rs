use ampd::types::Hash;
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::msg_id::Base58SolanaTxSignatureAndEventIndex;
use multisig::verifier_set::VerifierSet;
use serde::Deserialize;
use solana_sdk::pubkey::Pubkey;

#[derive(Clone, Deserialize, Debug)]
pub struct Message {
    pub message_id: Base58SolanaTxSignatureAndEventIndex,
    pub destination_address: String,
    pub destination_chain: ChainName,
    #[serde(deserialize_with = "crate::solana::deserialize_pubkey")]
    pub source_address: Pubkey,
    pub payload_hash: Hash,
}

#[derive(Clone, Deserialize, Debug)]
pub struct VerifierSetConfirmation {
    pub message_id: Base58SolanaTxSignatureAndEventIndex,
    pub verifier_set: VerifierSet,
}
