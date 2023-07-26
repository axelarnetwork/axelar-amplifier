use std::fmt::Display;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint256, Uint64};
use multisig::types::Signature;

#[cw_serde]
pub enum CommandType {
    ApproveContractCall,
}

#[cw_serde]
pub struct Command {
    pub id: HexBinary,
    pub command_type: CommandType,
    pub command_params: HexBinary,
}

impl Display for CommandType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandType::ApproveContractCall => write!(f, "approveContractCall"),
        }
    }
}

#[cw_serde]
pub struct Data {
    pub destination_chain_id: Uint256,
    pub commands: Vec<Command>,
}

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
