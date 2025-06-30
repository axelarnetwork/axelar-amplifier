use cosmwasm_schema::cw_serde;
use cosmwasm_std::HexBinary;
use interchain_token_api::primitives::HubMessage;

// This could theoertically be moved to it's own package. However, this would require moving HubMessage, and
// probably other ITS types to their own package as well. Unclear if this level of modularization is worth it.
#[cw_serde]
pub enum TranslationQueryMsg {
    FromBytes { payload: HexBinary },
    ToBytes { message: HubMessage },
}
