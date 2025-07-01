use cosmwasm_std::{CosmosMsg, HexBinary};
use error_stack::ResultExt;
use interchain_token::primitives::HubMessage;

use super::msg::QueryMsg;

type Result<T> = error_stack::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to query translation contract to decode payload from bytes")]
    FromBytes,
    #[error("failed to query translation contract to encode message to bytes")]
    ToBytes,
}

impl From<QueryMsg> for Error {
    fn from(value: QueryMsg) -> Self {
        match value {
            QueryMsg::FromBytes { .. } => Error::FromBytes,
            QueryMsg::ToBytes { .. } => Error::ToBytes,
        }
    }
}

impl<'a> From<client::ContractClient<'a, CosmosMsg, QueryMsg>> for Client<'a> {
    fn from(client: client::ContractClient<'a, CosmosMsg, QueryMsg>) -> Self {
        Client { client }
    }
}

pub struct Client<'a> {
    client: client::ContractClient<'a, CosmosMsg, QueryMsg>,
}

impl Client<'_> {
    /// Query the translation contract to decode a chain-specific payload into a HubMessage
    pub fn from_bytes(&self, payload: HexBinary) -> Result<HubMessage> {
        let msg = QueryMsg::FromBytes { payload };
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }

    /// Query the translation contract to encode a HubMessage into a chain-specific payload
    pub fn to_bytes(&self, message: HubMessage) -> Result<HexBinary> {
        let msg = QueryMsg::ToBytes { message };
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }
}
