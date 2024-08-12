use cosmwasm_std::Addr;
use cw_multi_test::{App, ContractWrapper, Executor};

use crate::contract::Contract;

#[derive(Clone)]
pub struct RouterContract {
    pub contract_addr: Addr,
}

impl RouterContract {
    pub fn instantiate_contract(app: &mut App, admin: Addr, governance: Addr, nexus: Addr) -> Self {
        let code = ContractWrapper::new(
            router::contract::execute,
            router::contract::instantiate,
            router::contract::query,
        );
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("router"),
                &router::msg::InstantiateMsg {
                    admin_address: admin.to_string(),
                    governance_address: governance.to_string(),
                    nexus_gateway: nexus.to_string(),
                },
                &[],
                "router",
                None,
            )
            .unwrap();

        RouterContract { contract_addr }
    }
}

impl Contract for RouterContract {
    type QMsg = router_api::msg::QueryMsg;
    type ExMsg = router_api::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
