use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint64};
use msgs_derive::Permissions;

#[cw_serde]
#[derive(Permissions)]
pub enum ExecuteMsg {
    #[permission(Any)]
    VerifySignature {
        signature: HexBinary,
        message: HexBinary,
        public_key: HexBinary,
        signer_address: String,
        session_id: Uint64,
    },
}
