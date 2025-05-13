use coordinator::contract::{execute, instantiate, query};
use cosmwasm_std::testing::MockApi;
use cosmwasm_std::Addr;
use cw_multi_test::{ContractWrapper, Executor};

use crate::contract::Contract;
use crate::protocol::AxelarApp;

#[derive(Clone)]
pub struct CoordinatorContract {
    pub contract_addr: Addr,
}

impl CoordinatorContract {
    pub fn instantiate_contract(
        app: &mut AxelarApp,
        governance: Addr,
        service_registry: Addr,
        router: Addr,
        multisig: Addr,
    ) -> Self {
        let code = ContractWrapper::new_with_empty(execute, instantiate, query);
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                MockApi::default().addr_make("anyone"),
                &coordinator::msg::InstantiateMsg {
                    governance_address: governance.to_string(),
                    service_registry: service_registry.to_string(),
                    router_address: router.to_string(),
                    multisig_address: multisig.to_string(),
                },
                &[],
                "coordinator",
                None,
            )
            .unwrap();

        CoordinatorContract { contract_addr }
    }
}

impl Contract for CoordinatorContract {
    type QMsg = coordinator::msg::QueryMsg;
    type ExMsg = coordinator::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
