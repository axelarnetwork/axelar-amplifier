use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::HexBinary;
use interchain_token::primitives::HubMessage;

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(HubMessage)]
    FromBytes { payload: HexBinary },
    #[returns(HexBinary)]
    ToBytes { message: HubMessage },
}
