use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
use multisig::verifier_set::VerifierSet;
use serde::Deserialize;
use serde_with::{serde_as, DisplayFromStr};
use stellar_xdr::curr::{ScAddress, ScBytes, ScString};

#[serde_as]
#[derive(Deserialize, Debug, Clone)]
pub struct Message {
    pub message_id: HexTxHashAndEventIndex,
    pub destination_address: ScString,
    pub destination_chain: ChainName,
    #[serde_as(as = "DisplayFromStr")]
    pub source_address: ScAddress,
    pub payload_hash: ScBytes,
}

#[derive(Clone, Debug, Deserialize)]
pub struct VerifierSetConfirmation {
    pub message_id: HexTxHashAndEventIndex,
    pub verifier_set: VerifierSet,
}
