use axelar_wasm_std::msg_id::MessageIdFormat;
use cosmwasm_schema::{cw_serde, QueryResponses};

use crate::primitives::*;

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(ChainEndpoint)]
    GetChainInfo(ChainName),

    // Returns a list of chains registered with the router
    // The list is paginated by:
    // - start_after: the chain name to start after, which the next page of results should start.
    // - limit: limit the number of chains returned, default is u32::MAX.
    #[returns(Vec<ChainEndpoint>)]
    Chains {
        start_after: Option<ChainName>,
        limit: Option<u32>,
    },
}
