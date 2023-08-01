use std::fmt::Display;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint256};
use multisig::types::Signature;

use crate::encoding::Data;

#[cw_serde]
pub enum CommandType {
    ApproveContractCall,
}

impl Display for CommandType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandType::ApproveContractCall => write!(f, "approveContractCall"),
        }
    }
}

#[cw_serde]
pub struct Command {
    pub id: HexBinary,
    pub command_type: CommandType,
    pub params: HexBinary,
}

#[cw_serde]
pub struct CommandBatch {
    pub id: HexBinary,
    pub message_ids: Vec<String>,
    pub data: Data,
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
