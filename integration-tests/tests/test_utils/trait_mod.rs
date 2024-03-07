use cosmwasm_std::Addr;
use cw_multi_test::{App, ContractWrapper, Executor};
use integration_tests::contract::Contract;
use service_registry::contract::{execute, instantiate, query};

#[derive(Clone)]
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
                &service_registry::msg::InstantiateMsg {
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

impl Contract for ServiceRegistryContract {
    type QMsg = service_registry::msg::QueryMsg;
    type ExMsg = service_registry::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}

#[derive(Clone)]
pub struct ConnectionRouterContract {
    pub contract_addr: Addr,
}

impl ConnectionRouterContract {
    pub fn instantiate_contract(app: &mut App, admin: Addr, governance: Addr, nexus: Addr) -> Self {
        let code = ContractWrapper::new(
            connection_router::contract::execute,
            connection_router::contract::instantiate,
            connection_router::contract::query,
        );
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("router"),
                &connection_router::msg::InstantiateMsg {
                    admin_address: admin.to_string(),
                    governance_address: governance.to_string(),
                    nexus_gateway: nexus.to_string(),
                },
                &[],
                "connection_router",
                None,
            )
            .unwrap();

        ConnectionRouterContract { contract_addr }
    }
}

impl Contract for ConnectionRouterContract {
    type QMsg = connection_router_api::msg::QueryMsg;
    type ExMsg = connection_router_api::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}

#[derive(Clone)]
pub struct RewardsContract {
    pub contract_addr: Addr,
}

impl RewardsContract {
    pub fn instantiate_contract(
        app: &mut App,
        governance: Addr,
        rewards_denom: String,
        params: rewards::msg::Params,
    ) -> Self {
        let code = ContractWrapper::new(
            rewards::contract::execute,
            rewards::contract::instantiate,
            connection_router::contract::query,
        );
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("anyone"),
                &rewards::msg::InstantiateMsg {
                    governance_address: governance.to_string(),
                    rewards_denom,
                    params,
                },
                &[],
                "rewards",
                None,
            )
            .unwrap();

        RewardsContract { contract_addr }
    }
}

impl Contract for RewardsContract {
    type QMsg = rewards::msg::QueryMsg;
    type ExMsg = rewards::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
