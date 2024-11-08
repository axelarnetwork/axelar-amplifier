use cosmwasm_std::Addr;
use cw_multi_test::{ContractWrapper, Executor};
use router_api::ChainName;
use xrpl_types::types::XRPLAccountId;

use crate::{contract::Contract, protocol::AxelarApp};

#[derive(Clone)]
pub struct XRPLGatewayContract {
    pub contract_addr: Addr,
}

impl XRPLGatewayContract {
    pub fn instantiate_contract(
        app: &mut AxelarApp,
        router_address: Addr,
        verifier_address: Addr,
        its_hub_address: Addr,
        axelar_chain_name: ChainName,
        xrpl_chain_name: ChainName,
        xrpl_multisig_address: XRPLAccountId,
    ) -> Self {
        let code = ContractWrapper::new_with_empty(
            xrpl_gateway::contract::execute,
            xrpl_gateway::contract::instantiate,
            xrpl_gateway::contract::query,
        );
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("anyone"),
                &xrpl_gateway::msg::InstantiateMsg {
                    router_address: router_address.to_string(),
                    verifier_address: verifier_address.to_string(),
                    its_hub_address: its_hub_address.to_string(),
                    axelar_chain_name,
                    xrpl_chain_name,
                    xrpl_multisig_address,
                },
                &[],
                "xrpl_gateway",
                None,
            )
            .unwrap();

        XRPLGatewayContract { contract_addr }
    }
}

impl Contract for XRPLGatewayContract {
    type QMsg = xrpl_gateway::msg::QueryMsg;
    type ExMsg = xrpl_gateway::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
