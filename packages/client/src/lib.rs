use std::marker::PhantomData;

use cosmwasm_std::{to_json_binary, Addr, QuerierWrapper, QueryRequest, WasmMsg, WasmQuery};
use error_stack::{Result, ResultExt};
use serde::{de::DeserializeOwned, Serialize};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("could not query the contract")]
    Query,
}

pub struct Client<'a, M, Q>
where
    M: Serialize,
    Q: Serialize,
{
    pub querier: QuerierWrapper<'a>,
    pub address: Addr,
    execute_msg_type: PhantomData<M>,
    query_msg_type: PhantomData<Q>,
}

impl<'a, M, Q> Client<'a, M, Q>
where
    M: Serialize,
    Q: Serialize,
{
    pub fn new(querier: QuerierWrapper<'a>, address: Addr) -> Self {
        Client {
            querier,
            address,
            execute_msg_type: PhantomData,
            query_msg_type: PhantomData,
        }
    }

    pub fn execute(&self, msg: &M) -> WasmMsg {
        WasmMsg::Execute {
            contract_addr: self.address.to_string(),
            msg: to_json_binary(msg).expect("msg should always be serializable"),
            funds: vec![],
        }
    }

    pub fn query<R>(&self, msg: &Q) -> Result<R, Error>
    where
        R: DeserializeOwned,
    {
        self.querier
            .query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: self.address.to_string(),
                msg: to_json_binary(msg).expect("msg should always be serializable"),
            }))
            .change_context(Error::Query)
    }
}
