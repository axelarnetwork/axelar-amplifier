use axelar_core_std::query::AxelarQueryMsg;
use axelar_wasm_std::error::ContractError;
use cosmwasm_std::{Addr, DepsMut, Env, MessageInfo, Response};
use cw_multi_test::{ContractWrapper, Executor};

use crate::contract::Contract;
use crate::protocol::{emptying_deps, emptying_deps_mut, AxelarApp};

#[derive(Clone)]
pub struct ServiceRegistryContract {
    pub contract_addr: Addr,
}

impl ServiceRegistryContract {
    pub fn instantiate_contract(app: &mut AxelarApp, governance: Addr) -> Self {
        let code = ContractWrapper::new(custom_execute, custom_instantiate, custom_query);
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("anyone"),
                &service_registry::msg::InstantiateMsg {
                    governance_account: governance.clone().into(),
                },
                &[],
                "service_registry",
                None,
            )
            .unwrap();

        ServiceRegistryContract { contract_addr }
    }
}

fn custom_execute(
    mut deps: DepsMut<AxelarQueryMsg>,
    env: Env,
    info: MessageInfo,
    msg: service_registry::msg::ExecuteMsg,
) -> Result<Response, ContractError> {
    service_registry::contract::execute(emptying_deps_mut(&mut deps), env, info, msg)
}

fn custom_instantiate(
    mut deps: DepsMut<AxelarQueryMsg>,
    env: Env,
    info: MessageInfo,
    msg: service_registry::msg::InstantiateMsg,
) -> Result<Response, ContractError> {
    service_registry::contract::instantiate(emptying_deps_mut(&mut deps), env, info, msg)
}

fn custom_query(
    deps: cosmwasm_std::Deps<AxelarQueryMsg>,
    env: Env,
    msg: service_registry::msg::QueryMsg,
) -> Result<cosmwasm_std::Binary, ContractError> {
    service_registry::contract::query(emptying_deps(&deps), env, msg)
}

impl Contract for ServiceRegistryContract {
    type QMsg = service_registry_api::msg::QueryMsg;
    type ExMsg = service_registry_api::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
