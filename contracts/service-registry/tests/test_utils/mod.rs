use cosmwasm_std::{Addr, Coin};
use cw_multi_test::{App, AppResponse, ContractWrapper, Executor};
use error_stack::{report, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use service_registry::{
    contract::{execute, instantiate, query},
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
};

pub struct ServiceRegistryContract {
    pub contract_addr: Addr,
}

impl ServiceRegistryContract {
    pub fn instantiate_contract(app: &mut App, governance: Addr) -> Self {
        let code = ContractWrapper::new(execute, instantiate, query);
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("anyone"),
                &InstantiateMsg {
                    governance_account: governance.clone().into(),
                },
                &[],
                "service_registry",
                None,
            )
            .unwrap();

        ServiceRegistryContract { contract_addr }
    }
}

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

impl Contract for ServiceRegistryContract {
    type QMsg = QueryMsg;
    type ExMsg = ExecuteMsg;
    type Err = axelar_wasm_std::ContractError;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
