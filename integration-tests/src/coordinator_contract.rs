use axelar_core_std::query::AxelarQueryMsg;
use axelar_wasm_std::error::ContractError;
use cosmwasm_std::{Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response};
use cw_multi_test::{ContractWrapper, Executor};

use crate::contract::Contract;
use crate::protocol::{emptying_deps, emptying_deps_mut, AxelarApp};

#[derive(Clone)]
pub struct CoordinatorContract {
    pub contract_addr: Addr,
}

impl CoordinatorContract {
    pub fn instantiate_contract(app: &mut AxelarApp, governance: Addr) -> Self {
        let code = ContractWrapper::new(custom_execute, custom_instantiate, custom_query);
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

fn custom_execute(
    mut deps: DepsMut<AxelarQueryMsg>,
    env: Env,
    info: MessageInfo,
    msg: coordinator::msg::ExecuteMsg,
) -> Result<Response, ContractError> {
    coordinator::contract::execute(emptying_deps_mut(&mut deps), env, info, msg)
}

fn custom_instantiate(
    mut deps: DepsMut<AxelarQueryMsg>,
    env: Env,
    info: MessageInfo,
    msg: coordinator::msg::InstantiateMsg,
) -> Result<Response, ContractError> {
    coordinator::contract::instantiate(emptying_deps_mut(&mut deps), env, info, msg)
}

fn custom_query(
    deps: Deps<AxelarQueryMsg>,
    env: Env,
    msg: coordinator::msg::QueryMsg,
) -> Result<Binary, ContractError> {
    coordinator::contract::query(emptying_deps(&deps), env, msg)
}
impl Contract for CoordinatorContract {
    type QMsg = coordinator::msg::QueryMsg;
    type ExMsg = coordinator::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
