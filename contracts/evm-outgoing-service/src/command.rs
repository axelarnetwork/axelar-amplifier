use std::fmt::Display;

use cosmwasm_schema::cw_serde;

#[cw_serde]
pub enum CommandType {
    ValidateCallsHash {
        source_chain: String,
        calls_hash: [u8; 32],
    },
}

impl Display for CommandType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandType::ValidateCallsHash {
                source_chain: _,
                calls_hash: _,
            } => write!(f, "validateCallsHash"),
        }
    }
}

#[cw_serde]
pub struct Command {
    pub command_id: [u8; 32],
    pub params: Vec<u8>,   // TODO: keyId
    pub max_gas_cost: u32, // TODO: is necessary for cosmwasm?
    pub command_type: String,
}
