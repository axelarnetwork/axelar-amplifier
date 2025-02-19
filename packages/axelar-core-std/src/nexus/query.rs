use std::fmt::Debug;

use cosmwasm_std::QueryRequest;
use serde::{Deserialize, Serialize};

#[non_exhaustive]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    // TxHashAndNonce returns the tx hash and nonce of the current transaction
    // Note that the empty struct is used to be able to work for Golang
    TxHashAndNonce {},

    // IsChainRegistered returns if the chain is already registered in core
    IsChainRegistered { chain: String },
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct TxHashAndNonceResponse {
    pub tx_hash: [u8; 32],
    pub nonce: u64,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct IsChainRegisteredResponse {
    pub is_registered: bool,
}

impl From<QueryMsg> for QueryRequest<crate::query::AxelarQueryMsg> {
    fn from(msg: QueryMsg) -> QueryRequest<crate::query::AxelarQueryMsg> {
        crate::query::AxelarQueryMsg::Nexus(msg).into()
    }
}
