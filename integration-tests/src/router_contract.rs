use axelar_core_std::query::AxelarQueryMsg;
use axelar_wasm_std::error::ContractError;
use cosmwasm_std::{Addr, DepsMut, Env, MessageInfo, Response};
use cw_multi_test::{ContractWrapper, Executor};

use crate::contract::Contract;
use crate::protocol::{emptying_deps, emptying_deps_mut, AxelarApp};

#[derive(Clone)]
pub struct RouterContract {
    pub contract_addr: Addr,
}

impl RouterContract {
    pub fn instantiate_contract(
        app: &mut AxelarApp,
        admin: Addr,
        governance: Addr,
        nexus: Addr,
    ) -> Self {
        let code = ContractWrapper::new(custom_execute, custom_instantiate, custom_query);
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("router"),
                &router::msg::InstantiateMsg {
                    admin_address: admin.to_string(),
                    governance_address: governance.to_string(),
                    nexus_gateway: nexus.to_string(),
                },
                &[],
                "router",
                None,
            )
            .unwrap();

        RouterContract { contract_addr }
    }
}

fn custom_execute(
    mut deps: DepsMut<AxelarQueryMsg>,
    env: Env,
    info: MessageInfo,
    msg: router::msg::ExecuteMsg,
) -> Result<Response, ContractError> {
    router::contract::execute(emptying_deps_mut(&mut deps), env, info, msg)
}

fn custom_instantiate(
    mut deps: DepsMut<AxelarQueryMsg>,
    env: Env,
    info: MessageInfo,
    msg: router::msg::InstantiateMsg,
) -> Result<Response, ContractError> {
    router::contract::instantiate(emptying_deps_mut(&mut deps), env, info, msg)
}

fn custom_query(
    deps: cosmwasm_std::Deps<AxelarQueryMsg>,
    env: Env,
    msg: router::msg::QueryMsg,
) -> Result<cosmwasm_std::Binary, ContractError> {
    router::contract::query(emptying_deps(&deps), env, msg)
}

impl Contract for RouterContract {
    type QMsg = router_api::msg::QueryMsg;
    type ExMsg = router_api::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
