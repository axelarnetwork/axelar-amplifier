use axelar_core_std::query::AxelarQueryMsg;
use axelar_wasm_std::error::ContractError;
use cosmwasm_std::{Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response};
use cw_multi_test::{ContractWrapper, Executor};

use crate::contract::Contract;
use crate::protocol::{emptying_deps, emptying_deps_mut, CustomApp};

#[derive(Clone)]
pub struct GatewayContract {
    pub contract_addr: Addr,
}

impl GatewayContract {
    pub fn instantiate_contract(
        app: &mut CustomApp,
        router_address: Addr,
        verifier_address: Addr,
    ) -> Self {
        let code = ContractWrapper::new(custom_execute, custom_instantiate, custom_query);
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

fn custom_execute(
    mut deps: DepsMut<AxelarQueryMsg>,
    env: Env,
    info: MessageInfo,
    msg: gateway::msg::ExecuteMsg,
) -> Result<Response, ContractError> {
    gateway::contract::execute(emptying_deps_mut(&mut deps), env, info, msg)
}

fn custom_instantiate(
    mut deps: DepsMut<AxelarQueryMsg>,
    env: Env,
    info: MessageInfo,
    msg: gateway::msg::InstantiateMsg,
) -> Result<Response, ContractError> {
    gateway::contract::instantiate(emptying_deps_mut(&mut deps), env, info, msg)
}

fn custom_query(
    deps: Deps<AxelarQueryMsg>,
    env: Env,
    msg: gateway::msg::QueryMsg,
) -> Result<Binary, ContractError> {
    gateway::contract::query(emptying_deps(&deps), env, msg)
}

impl Contract for GatewayContract {
    type QMsg = gateway_api::msg::QueryMsg;
    type ExMsg = gateway_api::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
