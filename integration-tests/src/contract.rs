use cosmwasm_std::{Addr, Coin};
use cw_multi_test::{App, AppResponse, Executor};
use error_stack::{report, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;

pub trait Contract {
    type QMsg;
    type ExMsg;
    type Err;

    fn contract_address(&self) -> Addr;
    fn query<T: DeserializeOwned>(&self, app: &App, query_message: &Self::QMsg) -> T
    where
        Self::QMsg: Serialize,
    {
        app.wrap()
            .query_wasm_smart(self.contract_address(), query_message)
            .unwrap()
    }

    fn execute(
        &self,
        app: &mut App,
        caller: Addr,
        execute_message: &Self::ExMsg,
    ) -> Result<AppResponse, Self::Err>
    where
        Self::ExMsg: Serialize,
        Self::ExMsg: std::fmt::Debug,
        Self::Err: error_stack::Context,
    {
        self.execute_with_funds(app, caller, execute_message, &[])
    }

    fn execute_with_funds(
        &self,
        app: &mut App,
        caller: Addr,
        execute_message: &Self::ExMsg,
        funds: &[Coin],
    ) -> Result<AppResponse, Self::Err>
    where
        Self::ExMsg: Serialize,
        Self::ExMsg: std::fmt::Debug,
        Self::Err: error_stack::Context,
    {
        app.execute_contract(
            caller.clone(),
            self.contract_address(),
            execute_message,
            funds,
        )
        .map_err(|err| report!(err.downcast::<Self::Err>().unwrap()))
    }
}
