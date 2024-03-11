use crate::contract::Contract;
use cosmwasm_std::Addr;
use cw_multi_test::{App, ContractWrapper, Executor};

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
