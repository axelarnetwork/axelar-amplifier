use cosmwasm_schema::cw_serde;
use cosmwasm_std::HexBinary;

use crate::primitives::HubMessage;

#[cw_serde]
pub enum TranslationQueryMsg {
    FromBytes { payload: HexBinary },
    ToBytes { message: HubMessage },
}
