use std::marker::PhantomData;

use cosmwasm_schema::serde::de::DeserializeOwned;
use cosmwasm_std::{
    to_json_binary, Addr, Empty, HexBinary, QuerierWrapper, QueryRequest, WasmQuery,
};
use error_stack::{Result, ResultExt};

use super::msg::TranslationQueryMsg;
use crate::HubMessage;

#[derive(Clone)]
pub struct TranslationContract<'a, T = Empty> {
    pub address: Addr,
    pub querier: QuerierWrapper<'a>,
    custom_msg_type: PhantomData<T>,
}

impl<'a, T> TranslationContract<'a, T> {
    pub fn new(address: Addr, querier: QuerierWrapper<'a>) -> Self {
        TranslationContract::<'a, T> {
            address,
            querier,
            custom_msg_type: PhantomData,
        }
    }

    fn query<U: DeserializeOwned + 'static>(&self, msg: &TranslationQueryMsg) -> Result<U, Error> {
        self.querier
            .query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: self.address.to_string(),
                msg: to_json_binary(msg).expect("msg should always be serializable"),
            }))
            .change_context(Error::QueryTranslationContract)
    }

    /// Query the translation contract to decode a chain-specific payload into a HubMessage
    pub fn from_bytes(&self, payload: HexBinary) -> Result<HubMessage, Error> {
        self.query(&TranslationQueryMsg::FromBytes { payload })
    }

    /// Query the translation contract to encode a HubMessage into a chain-specific payload
    pub fn to_bytes(&self, message: HubMessage) -> Result<HexBinary, Error> {
        self.query(&TranslationQueryMsg::ToBytes { message })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("could not query the translation contract")]
    QueryTranslationContract,
}
