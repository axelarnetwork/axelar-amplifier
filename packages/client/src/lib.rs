use std::marker::PhantomData;
use std::ops::Deref;

use cosmwasm_std::{
    to_json_binary, Addr, Coin, CosmosMsg, CustomQuery, Empty, QuerierWrapper, QueryRequest,
    StdError, WasmMsg, WasmQuery,
};
use error_stack::{Report, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    QueryFailed(#[from] StdError),
}

pub struct CosmosClient<'a, T = Empty> {
    querier: QuerierWrapper<'a>,
    custom_msg_type: PhantomData<T>,
}

impl<'a, T> CosmosClient<'a, T> {
    pub fn new(querier: QuerierWrapper<'a>) -> Self {
        Self {
            querier,
            custom_msg_type: PhantomData,
        }
    }

    pub fn execute<M>(&self, msg: M) -> CosmosMsg<T>
    where
        M: Into<CosmosMsg<T>>,
    {
        msg.into()
    }

    pub fn query<R, Q, C>(&self, msg: Q) -> Result<R, Error>
    where
        R: DeserializeOwned,
        Q: Into<QueryRequest<C>>,
        C: CustomQuery,
    {
        QuerierWrapper::new(self.querier.deref())
            .query(&msg.into())
            .map_err(Into::into)
            .map_err(Report::new)
    }
}

pub struct ContractClient<'a, M, Q, T = Empty>
where
    M: Serialize,
    Q: Serialize,
{
    inner: CosmosClient<'a, T>,
    pub address: &'a Addr,
    execute_msg_type: PhantomData<M>,
    query_msg_type: PhantomData<Q>,
}

impl<'a, M, Q, T> ContractClient<'a, M, Q, T>
where
    M: Serialize,
    Q: Serialize,
{
    pub fn new(querier: QuerierWrapper<'a>, address: &'a Addr) -> Self {
        Self {
            inner: CosmosClient::new(querier),
            address,
            execute_msg_type: PhantomData,
            query_msg_type: PhantomData,
        }
    }

    pub fn execute(&self, msg: &M) -> CosmosMsg<T> {
        self.inner.execute(WasmMsg::Execute {
            contract_addr: self.address.to_string(),
            msg: to_json_binary(msg).expect("msg should always be serializable"),
            funds: vec![],
        })
    }

    pub fn execute_with_funds(&self, msg: &M, coin: Coin) -> CosmosMsg<T> {
        self.inner.execute(WasmMsg::Execute {
            contract_addr: self.address.to_string(),
            msg: to_json_binary(msg).expect("msg should always be serializable"),
            funds: vec![coin],
        })
    }

    pub fn query<R>(&self, msg: &Q) -> Result<R, Error>
    where
        R: DeserializeOwned,
    {
        self.inner
            .query::<_, _, Empty>(QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: self.address.to_string(),
                msg: to_json_binary(msg).expect("msg should always be serializable"),
            }))
    }
}
