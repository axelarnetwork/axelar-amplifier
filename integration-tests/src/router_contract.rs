use cosmwasm_std::Addr;
use cw_multi_test::{ContractWrapper, Executor};
use router::contract::{execute, instantiate, query};

use crate::contract::Contract;
use crate::protocol::AxelarApp;

#[derive(Clone)]
pub struct RouterContract {
    pub contract_addr: Addr,
}

impl RouterContract {
    pub fn instantiate_contract(
        app: &mut AxelarApp,
        admin: Addr,
        governance: Addr,
        axelarnet: Addr,
    ) -> Self {
        let code = ContractWrapper::new_with_empty(execute, instantiate, query);
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("router"),
                &router::msg::InstantiateMsg {
                    admin_address: admin.to_string(),
                    governance_address: governance.to_string(),
                    axelarnet_gateway: axelarnet.to_string(),
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
