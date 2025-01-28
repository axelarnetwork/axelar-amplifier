use cosmwasm_std::Addr;
use cw_multi_test::{ContractWrapper, Executor};

use crate::{contract::Contract, protocol::AxelarApp};

#[derive(Clone)]
pub struct InterchainTokenServiceContract {
    pub contract_addr: Addr,
}

impl InterchainTokenServiceContract {
    pub fn instantiate_contract(
        app: &mut AxelarApp,
        axelarnet_gateway: Addr,
        governance: Addr,
        admin: Addr,
    ) -> Self {
        let code = ContractWrapper::new_with_empty(
            interchain_token_service::contract::execute,
            interchain_token_service::contract::instantiate,
            interchain_token_service::contract::query,
        );
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("anyone"),
                &interchain_token_service::msg::InstantiateMsg {
                    axelarnet_gateway_address: axelarnet_gateway.to_string(),
                    governance_address: governance.to_string(),
                    admin_address: admin.to_string(),
                },
                &[],
                "interchain_token_service",
                None,
            )
            .unwrap();

        InterchainTokenServiceContract { contract_addr }
    }
}

impl Contract for InterchainTokenServiceContract {
    type QMsg = interchain_token_service::msg::QueryMsg;
    type ExMsg = interchain_token_service::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
