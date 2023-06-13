use std::collections::HashMap;

use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{HexBinary, Uint64};

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    StartSigningSession {
        sig_msg: HexBinary,
    },
    SubmitSignature {
        multisig_session_id: Uint64,
        signature: HexBinary,
    },
    CompleteSigningSession {
        multisig_session_id: Uint64,
    },
    SubmitKeySet {
        pub_keys: HashMap<String, HexBinary>,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {}
