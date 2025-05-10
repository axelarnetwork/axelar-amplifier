use std::collections::HashMap;

use axelar_wasm_std::msg_id::HexTxHash;
use axelar_wasm_std::IntoEvent;
use cosmwasm_std::{HexBinary, Uint64};
use multisig::key::PublicKey;
use router_api::{ChainName, CrossChainId};

#[derive(IntoEvent)]
pub enum Event {
    ProofUnderConstruction {
        destination_chain: ChainName,
        unsigned_tx_hash: HexTxHash,
        multisig_session_id: Uint64,
        message_ids: Option<Vec<CrossChainId>>,
    },
    XRPLSigningStarted {
        session_id: Uint64,
        verifier_set_id: String,
        pub_keys: HashMap<String, PublicKey>,
        unsigned_tx: HexBinary,
        expires_at: u64,
    },
    ExecutionDisabled,
    ExecutionEnabled,
}
