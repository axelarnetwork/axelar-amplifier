use std::collections::HashMap;

use axelar_wasm_std::msg_id::HexTxHash;
use axelar_wasm_std::{nonempty, IntoEvent};
use cosmwasm_std::{HexBinary, Uint64};
use interchain_token_service_std::TokenId;
use multisig::key::PublicKey;
use router_api::{ChainName, ChainNameRaw, CrossChainId};
use xrpl_types::types::{XRPLAccountId, XRPLPaymentAmount, XRPLToken};

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
    InterchainTransferReceived {
        message_id: nonempty::String,
        token_id: TokenId,
        source_chain: ChainNameRaw,
        destination_address: XRPLAccountId,
        amount: XRPLPaymentAmount,
    },
    TicketsCreated {
        tx_id: nonempty::String,
        first: u32,
        last: u32,
    },
    TrustLineCreated {
        tx_id: nonempty::String,
        token_id: TokenId,
        token: XRPLToken,
    },
    VerifierSetUpdated {
        tx_id: nonempty::String,
        verifier_set_id: String,
        count: usize,
        quorum: u32,
    },
}
