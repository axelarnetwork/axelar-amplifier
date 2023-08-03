use std::collections::HashMap;

use axelar_wasm_std::Snapshot;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, HexBinary, Uint256, Uint64};

use crate::types::{MultisigState, PublicKey, Signature};

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    StartSigningSession {
        key_id: String,
        msg: HexBinary,
    },
    SubmitSignature {
        session_id: Uint64,
        signature: HexBinary,
    },
    KeyGen {
        key_id: String,
        snapshot: Snapshot,
        pub_keys: HashMap<String, HexBinary>,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Multisig)]
    GetMultisig { session_id: Uint64 },
}

#[cw_serde]
pub struct Signer {
    pub address: Addr,
    pub weight: Uint256,
    pub pub_key: PublicKey,
    pub signature: Option<Signature>,
}

#[cw_serde]
pub struct Multisig {
    pub state: MultisigState,
    pub quorum: Uint256,
    pub signers: Vec<Signer>,
}
