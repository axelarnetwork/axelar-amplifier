use cosmwasm_std::Addr;
use cw_multi_test::{App, ContractWrapper, Executor};

use crate::contract::Contract;

#[derive(Clone)]
pub struct GatewayContract {
    pub contract_addr: Addr,
}

impl GatewayContract {
    pub fn instantiate_contract(
        app: &mut App,
        router_address: Addr,
        verifier_address: Addr,
    ) -> Self {
        let code = ContractWrapper::new(
            gateway::contract::execute,
            gateway::contract::instantiate,
            gateway::contract::query,
        );
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("anyone"),
                &gateway::msg::InstantiateMsg {
                    router_address: router_address.to_string(),
                    verifier_address: verifier_address.to_string(),
                },
                &[],
                "gateway",
                None,
            )
            .unwrap();

        GatewayContract { contract_addr }
    }
}

impl Contract for GatewayContract {
    type QMsg = gateway_api::msg::QueryMsg;
    type ExMsg = gateway_api::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
