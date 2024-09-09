use std::fmt::Debug;

use cosmwasm_std::QueryRequest;
use serde::{Deserialize, Serialize};

#[non_exhaustive]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum QueryMsg {
    // TxHashAndNonce returns the tx hash and nonce of the current transaction
    // Note that the empty struct is used to be able to work for Golang
    TxHashAndNonce {},
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct TxHashAndNonceResponse {
    pub tx_hash: [u8; 32],
    pub nonce: u64,
}

impl From<QueryMsg> for QueryRequest<crate::query::QueryMsg> {
    fn from(msg: QueryMsg) -> QueryRequest<crate::query::QueryMsg> {
        crate::query::QueryMsg::Nexus(msg).into()
    }
}
