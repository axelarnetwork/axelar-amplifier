use axelar_core_std::query::AxelarQueryMsg;
use axelar_wasm_std::error;
use cosmwasm_std::{Addr, DepsMut, Env, MessageInfo, Response};
use cw_multi_test::{ContractWrapper, Executor};

use crate::contract::Contract;
use crate::protocol::{emptying_deps, emptying_deps_mut, CustomApp};

#[derive(Clone)]
pub struct RewardsContract {
    pub contract_addr: Addr,
}

impl RewardsContract {
    pub fn instantiate_contract(
        app: &mut CustomApp,
        governance: Addr,
        rewards_denom: String,
    ) -> Self {
        let code = ContractWrapper::new(custom_execute, custom_instantiate, custom_query);
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

fn custom_execute(
    mut deps: DepsMut<AxelarQueryMsg>,
    env: Env,
    info: MessageInfo,
    msg: rewards::msg::ExecuteMsg,
) -> Result<Response, error::ContractError> {
    rewards::contract::execute(emptying_deps_mut(&mut deps), env, info, msg)
}

fn custom_instantiate(
    mut deps: DepsMut<AxelarQueryMsg>,
    env: Env,
    info: MessageInfo,
    msg: rewards::msg::InstantiateMsg,
) -> Result<Response, error::ContractError> {
    rewards::contract::instantiate(emptying_deps_mut(&mut deps), env, info, msg)
}

fn custom_query(
    deps: cosmwasm_std::Deps<AxelarQueryMsg>,
    env: Env,
    msg: rewards::msg::QueryMsg,
) -> Result<cosmwasm_std::Binary, error::ContractError> {
    rewards::contract::query(emptying_deps(&deps), env, msg)
}

impl Contract for RewardsContract {
    type QMsg = rewards::msg::QueryMsg;
    type ExMsg = rewards::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
