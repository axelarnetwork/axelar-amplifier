use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, HexBinary, Uint256, Uint64};

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
    pub signing_session_id: Uint64,
}

#[cw_serde]
pub struct Proof {
    pub addresses: Vec<Addr>,
    pub weights: Vec<Uint256>,
    pub threshold: Uint256,
    pub signatures: Vec<HexBinary>,
}
