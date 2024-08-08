use cosmwasm_std::Addr;
use cw_multi_test::{App, ContractWrapper, Executor};

use crate::contract::Contract;

#[derive(Clone)]
pub struct RewardsContract {
    pub contract_addr: Addr,
}

impl RewardsContract {
    pub fn instantiate_contract(app: &mut App, governance: Addr, rewards_denom: String) -> Self {
        let code = ContractWrapper::new(
            rewards::contract::execute,
            rewards::contract::instantiate,
            rewards::contract::query,
        );
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("anyone"),
                &rewards::msg::InstantiateMsg {
                    governance_address: governance.to_string(),
                    rewards_denom,
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
