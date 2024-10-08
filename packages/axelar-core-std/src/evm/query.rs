use std::fmt::Debug;

use axelar_wasm_std::nonempty;
use cosmwasm_std::{QueryRequest, Uint256};
use router_api::ChainNameRaw;
use serde::{Deserialize, Serialize};

#[non_exhaustive]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    TokenInfo { chain: String, asset: String },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TokenInfoResponse {
    pub asset: String,
    pub address: String,
    pub details: TokenDetails,
    pub confirmed: bool,
    pub is_external: bool,
    pub burner_code_hash: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TokenDetails {
    pub token_name: String,
    pub symbol: String,
    pub decimals: u32,
    pub capacity: Uint256,
}

impl From<QueryMsg> for QueryRequest<crate::query::AxelarQueryMsg> {
    fn from(msg: QueryMsg) -> QueryRequest<crate::query::AxelarQueryMsg> {
        crate::query::AxelarQueryMsg::Evm(msg).into()
    }
}
