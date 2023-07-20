use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint256, Uint64};

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
pub struct Proof {
    pub operators: Vec<HexBinary>,
    pub weights: Vec<Uint256>,
    pub quorum: Uint256,
    pub signatures: Vec<HexBinary>,
}
