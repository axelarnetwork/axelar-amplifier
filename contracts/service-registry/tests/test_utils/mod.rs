use connection_router::state::ChainName;
use cosmwasm_std::{Addr};
use cw_multi_test::{App, ContractWrapper, Executor};
use serde::de::DeserializeOwned;
use serde::Serialize;
use service_registry::{
    contract::{execute, instantiate, query},
    msg::{InstantiateMsg, QueryMsg},
    state::Worker,
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

    pub fn get_active_workers(
        &self,
        app: &App,
        service_name: &str,
        chain_name: ChainName,
    ) -> Vec<Worker> {
        let worker_query = &QueryMsg::GetActiveWorkers {
            service_name: service_name.into(),
            chain_name,
        };
        self.query(app, worker_query)
    }
}

pub trait Contract {
    type Msg;

    fn contract_address(&self) -> Addr;
    fn query<T: DeserializeOwned>(&self, app: &App, query_message: &Self::Msg) -> T
    where
        Self::Msg: Serialize,
    {
        app.wrap()
            .query_wasm_smart(self.contract_address(), query_message)
            .unwrap()
    }
}

impl Contract for ServiceRegistryContract {
    type Msg = QueryMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
