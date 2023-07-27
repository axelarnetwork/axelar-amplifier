use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint256};

#[cw_serde]
pub struct Data {
    pub destination_chain_id: Uint256,
    pub commands_ids: Vec<[u8; 32]>,
    pub commands_types: Vec<String>,
    pub commands_params: Vec<HexBinary>,
}

#[cw_serde]
pub struct Operator {
    pub address: HexBinary,
    pub weight: Uint256,
    pub signature: Option<HexBinary>,
}

#[cw_serde]
pub struct Proof {
    pub operators: Vec<Operator>,
    pub threshold: Uint256,
}
