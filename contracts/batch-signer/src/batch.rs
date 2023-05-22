use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint64};

type KeccackHash = [u8; 32]; // TODO: move to axelar_wasm_std

#[cw_serde]
pub struct CommandBatch {
    pub id: KeccackHash,
    pub commands_ids: Vec<KeccackHash>,
    pub data_encoded: HexBinary,
    pub unsigned_hash: KeccackHash,
    pub signing_session_id: Uint64,
}
