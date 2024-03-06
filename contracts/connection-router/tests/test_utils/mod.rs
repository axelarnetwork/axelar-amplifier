use connection_router::{
    contract::{execute, instantiate, query},
    msg::InstantiateMsg,
};
use connection_router_api::msg::{ExecuteMsg, QueryMsg};
use cosmwasm_std::Addr;
use cw_multi_test::{App, ContractWrapper, Executor};
use integration_tests::contract::Contract;

#[derive(Clone)]
pub struct ConnectionRouterContract {
    pub contract_addr: Addr,
}

impl ConnectionRouterContract {
    pub fn instantiate_contract(app: &mut App, admin: Addr, governance: Addr, nexus: Addr) -> Self {
        let code = ContractWrapper::new(execute, instantiate, query);
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("router"),
                &InstantiateMsg {
                    admin_address: admin.to_string(),
                    governance_address: governance.to_string(),
                    nexus_gateway: nexus.to_string(),
                },
                &[],
                "Contract",
                None,
            )
            .unwrap();

        ConnectionRouterContract { contract_addr }
    }
}

impl Contract for ConnectionRouterContract {
    type QMsg = QueryMsg;
    type ExMsg = ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}

pub fn are_contract_err_strings_equal(
    actual: impl Into<axelar_wasm_std::ContractError>,
    expected: impl Into<axelar_wasm_std::ContractError>,
) {
    assert_eq!(actual.into().to_string(), expected.into().to_string());
}
