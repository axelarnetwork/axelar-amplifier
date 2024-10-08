use axelar_wasm_std::nonempty;
use cosmwasm_std::CosmosMsg;
use error_stack::ResultExt;
use query::{QueryMsg, TokenInfoResponse};
use router_api::{ChainName, ChainNameRaw};

use crate::query::AxelarQueryMsg;

pub mod query;

type Result<T> = error_stack::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to query token info")]
    QueryTokenInfo,
}

pub struct Client<'a> {
    inner: client::CosmosClient<'a>,
}

impl<'a> From<client::CosmosClient<'a>> for Client<'a> {
    fn from(inner: client::CosmosClient<'a>) -> Self {
        Client { inner }
    }
}

impl<'a> Client<'a> {
    pub fn token_info(
        &self,
        chain: &ChainNameRaw,
        asset: nonempty::String,
    ) -> Result<query::TokenInfoResponse> {
        self.inner
            .query::<TokenInfoResponse, QueryMsg, AxelarQueryMsg>(QueryMsg::TokenInfo {
                chain: chain.to_string(),
                asset: asset.to_string(),
            })
            .change_context(Error::QueryTokenInfo)
    }
}
