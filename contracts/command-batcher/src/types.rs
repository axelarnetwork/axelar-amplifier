use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint256, Uint64};
use multisig::types::Signature;

use crate::encoding::Data;

#[cw_serde]
pub struct CommandBatch {
    pub id: HexBinary,
    pub message_ids: Vec<String>,
    pub data: Data,
    pub msg_to_sign: HexBinary,
    pub multisig_session_id: Option<Uint64>,
}

#[cw_serde]
pub struct Operator {
    pub address: HexBinary,
    pub weight: Uint256,
    pub signature: Option<Signature>,
}

#[cw_serde]
pub struct Proof {
    pub operators: Vec<Operator>,
    pub threshold: Uint256,
}
