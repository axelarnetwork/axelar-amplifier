use axelar_core_std::query::AxelarQueryMsg;
use axelar_wasm_std::nonempty;
use cosmwasm_std::{Addr, Deps, DepsMut, Env, MessageInfo};
use cw_multi_test::{ContractWrapper, Executor};

use crate::contract::Contract;
use crate::protocol::{emptying_deps, emptying_deps_mut, AxelarApp};

#[derive(Clone)]
pub struct MultisigContract {
    pub contract_addr: Addr,
}

impl MultisigContract {
    pub fn instantiate_contract(
        app: &mut AxelarApp,
        governance: Addr,
        admin: Addr,
        rewards_address: Addr,
        block_expiry: nonempty::Uint64,
    ) -> Self {
        let code = ContractWrapper::new(custom_execute, custom_instantiate, custom_query);
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("anyone"),
                &multisig::msg::InstantiateMsg {
                    rewards_address: rewards_address.to_string(),
                    governance_address: governance.to_string(),
                    admin_address: admin.to_string(),
                    block_expiry,
                },
                &[],
                "multisig",
                None,
            )
            .unwrap();

        MultisigContract { contract_addr }
    }
}

fn custom_execute(
    mut deps: DepsMut<AxelarQueryMsg>,
    env: Env,
    info: MessageInfo,
    msg: multisig::msg::ExecuteMsg,
) -> Result<cosmwasm_std::Response, axelar_wasm_std::error::ContractError> {
    multisig::contract::execute(emptying_deps_mut(&mut deps), env, info, msg)
}

fn custom_instantiate(
    mut deps: DepsMut<AxelarQueryMsg>,
    env: Env,
    info: MessageInfo,
    msg: multisig::msg::InstantiateMsg,
) -> Result<cosmwasm_std::Response, axelar_wasm_std::error::ContractError> {
    multisig::contract::instantiate(emptying_deps_mut(&mut deps), env, info, msg)
}

fn custom_query(
    deps: Deps<AxelarQueryMsg>,
    env: Env,
    msg: multisig::msg::QueryMsg,
) -> Result<cosmwasm_std::Binary, axelar_wasm_std::error::ContractError> {
    multisig::contract::query(emptying_deps(&deps), env, msg)
}

impl Contract for MultisigContract {
    type QMsg = multisig::msg::QueryMsg;
    type ExMsg = multisig::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
