use cosmwasm_std::{CosmosMsg, HexBinary};
use error_stack::ResultExt;
use interchain_token_api::primitives::HubMessage;

use super::msg::TranslationQueryMsg;

type Result<T> = error_stack::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to query translation contract to decode payload from bytes")]
    FromBytes,
    #[error("failed to query translation contract to encode message to bytes")]
    ToBytes,
}

impl From<TranslationQueryMsg> for Error {
    fn from(value: TranslationQueryMsg) -> Self {
        match value {
            TranslationQueryMsg::FromBytes { .. } => Error::FromBytes,
            TranslationQueryMsg::ToBytes { .. } => Error::ToBytes,
        }
    }
}

impl<'a> From<client::ContractClient<'a, CosmosMsg, TranslationQueryMsg>> for Client<'a> {
    fn from(client: client::ContractClient<'a, CosmosMsg, TranslationQueryMsg>) -> Self {
        Client { client }
    }
}

pub struct Client<'a> {
    client: client::ContractClient<'a, CosmosMsg, TranslationQueryMsg>,
}

impl Client<'_> {
    /// Query the translation contract to decode a chain-specific payload into a HubMessage
    pub fn from_bytes(&self, payload: HexBinary) -> Result<HubMessage> {
        let msg = TranslationQueryMsg::FromBytes { payload };
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }

    /// Query the translation contract to encode a HubMessage into a chain-specific payload
    pub fn to_bytes(&self, message: HubMessage) -> Result<HexBinary> {
        let msg = TranslationQueryMsg::ToBytes { message };
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }
}
