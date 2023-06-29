use std::collections::HashMap;

use axelar_wasm_std::Snapshot;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, HexBinary, Uint64};

use crate::types::{MultisigState, Signature};

#[cw_serde]
pub struct InstantiateMsg {
    pub admin_address: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    StartSigningSession {
        msg: HexBinary,
    },
    SubmitSignature {
        sig_id: Uint64,
        signature: HexBinary,
    },
    SetKey {
        // TODO: this will disappear once keygen and key rotation is introduced
        owner: Addr,
        snapshot: Snapshot,
        pub_keys: HashMap<String, HexBinary>,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(GetSigningSessionResponse)]
    GetSigningSession { sig_id: Uint64 },
}

#[cw_serde]
pub struct GetSigningSessionResponse {
    pub state: MultisigState,
    pub signatures: HashMap<String, Signature>,
    pub snapshot: Snapshot,
}
