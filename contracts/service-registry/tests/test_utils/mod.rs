use cosmwasm_std::{Addr, Coin};
use cw_multi_test::{App, AppResponse, ContractWrapper, Executor};
use error_stack::{report, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use service_registry::{
    contract::{execute, instantiate, query},
    error::ContractError,
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
    type Msg;
    type Exec;
    type Err;

    fn contract_address(&self) -> Addr;
    fn query<T: DeserializeOwned>(&self, app: &App, query_message: &Self::Msg) -> T
    where
        Self::Msg: Serialize,
    {
        app.wrap()
            .query_wasm_smart(self.contract_address(), query_message)
            .unwrap()
    }

    fn execute(
        &self,
        app: &mut App,
        caller: Addr,
        execute_message: &Self::Exec,
        funds: &[Coin],
    ) -> Result<AppResponse, Self::Err>
    where
        Self::Exec: Serialize,
        Self::Exec: std::fmt::Debug,
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
    type Msg = QueryMsg;
    type Exec = ExecuteMsg;
    type Err = ContractError;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
