use std::collections::HashMap;

use axelar_wasm_std::Snapshot;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{HexBinary, Uint64};

use crate::types::{MultisigState, Signature};

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
    #[returns(GetSigningSessionResponse)]
    GetSigningSession { session_id: Uint64 },
}

#[cw_serde]
pub struct GetSigningSessionResponse {
    pub state: MultisigState,
    pub signatures: HashMap<String, Signature>,
    pub snapshot: Snapshot,
}
