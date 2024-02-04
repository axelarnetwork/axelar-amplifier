use connection_router::state::ChainName;
use cosmwasm_std::Addr;
use cw_multi_test::{App, ContractWrapper, Executor};
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
        app.wrap()
            .query_wasm_smart(
                self.contract_addr.clone(),
                &QueryMsg::GetActiveWorkers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap()
    }
}
