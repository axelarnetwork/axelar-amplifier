use coordinator::contract::{execute, instantiate, query};
use cosmwasm_std::Addr;
use cw_multi_test::{App, ContractWrapper, Executor};

use crate::contract::Contract;

#[derive(Clone)]
pub struct CoordinatorContract {
    pub contract_addr: Addr,
}

impl CoordinatorContract {
    pub fn instantiate_contract(app: &mut App, governance: Addr) -> Self {
        let code = ContractWrapper::new(execute, instantiate, query);
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("anyone"),
                &coordinator::msg::InstantiateMsg {
                    governance_address: governance.to_string(),
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
