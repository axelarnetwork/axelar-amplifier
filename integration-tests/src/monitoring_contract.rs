use crate::contract::Contract;
use cosmwasm_std::Addr;
use cw_multi_test::{App, ContractWrapper, Executor};
use monitoring::contract::{execute, instantiate, query};

#[derive(Clone)]
pub struct MonitoringContract {
    pub contract_addr: Addr,
}

impl MonitoringContract {
    pub fn instantiate_contract(app: &mut App, governance: Addr) -> Self {
        let code = ContractWrapper::new(execute, instantiate, query);
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("anyone"),
                &monitoring::msg::InstantiateMsg {
                    governance_address: governance.to_string(),
                },
                &[],
                "monitoring",
                None,
            )
            .unwrap();

        MonitoringContract { contract_addr }
    }
}

impl Contract for MonitoringContract {
    type QMsg = monitoring::msg::QueryMsg;
    type ExMsg = monitoring::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
