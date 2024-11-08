use cosmwasm_std::Addr;
use cw_multi_test::{ContractWrapper, Executor};
use router_api::ChainName;
use axelarnet_gateway::contract::{execute, instantiate, query};

use crate::contract::Contract;
use crate::protocol::AxelarApp;

#[derive(Clone)]
pub struct AxelarnetGatewayContract {
    pub contract_addr: Addr,
}

impl AxelarnetGatewayContract {
    pub fn instantiate_contract(
        app: &mut AxelarApp,
        chain_name: ChainName,
        router_address: Addr,
        nexus_gateway: String,
    ) -> Self {
        let code = ContractWrapper::new_with_empty(execute, instantiate, query);
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("anyone"),
                &axelarnet_gateway::msg::InstantiateMsg {
                    chain_name,
                    router_address: router_address.to_string(),
                    nexus_gateway,
                },
                &[],
                "axelarnet_gateway",
                None,
            )
            .unwrap();

        AxelarnetGatewayContract { contract_addr }
    }
}

impl Contract for AxelarnetGatewayContract {
    type QMsg = axelarnet_gateway::msg::QueryMsg;
    type ExMsg = axelarnet_gateway::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
