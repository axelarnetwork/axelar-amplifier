use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, HexBinary, Uint256};

pub type KeccackHash = [u8; 32]; // TODO: move to axelar_wasm_std

#[cw_serde]
pub enum SigningStatus {
    Signing,
    Aborted,
    Signed,
}

#[cw_serde]
pub struct CommandBatch {
    pub id: KeccackHash,
    pub commands_ids: Vec<KeccackHash>,
    pub data_encoded: HexBinary,
    pub unsigned_hash: KeccackHash,
    pub status: SigningStatus,
}

#[cw_serde]
pub struct Proof {
    pub addresses: Vec<Addr>,
    pub weights: Vec<Uint256>,
    pub quorum: Uint256,
    pub signatures: Vec<HexBinary>,
}
