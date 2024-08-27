use std::fmt::Debug;

use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::{address, permission_control, FnExt, IntoContractError};
use axelarnet_gateway::AxelarExecutableMsg;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Addr, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response, Storage};
use error_stack::{Report, ResultExt};

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state;
use crate::state::Config;

mod execute;
mod query;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("failed to execute a cross-chain message")]
    Execute,
    #[error("failed to set an its address")]
    SetItsAddress,
    #[error("failed to remove an its address")]
    RemoveItsAddress,
    #[error("failed to query its address")]
    QueryItsAddress,
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(deps: DepsMut, _env: Env, _msg: Empty) -> Result<Response, ContractError> {
    // Implement migration logic if needed

    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _: Env,
    _: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let admin = deps.api.addr_validate(&msg.admin_address)?;
    let governance = deps.api.addr_validate(&msg.governance_address)?;

    permission_control::set_admin(deps.storage, &admin)?;
    permission_control::set_governance(deps.storage, &governance)?;

    let axelarnet_gateway =
        address::validate_cosmwasm_address(deps.api, &msg.axelarnet_gateway_address)?;

    state::save_config(deps.storage, &Config { axelarnet_gateway })?;

    for (chain, address) in msg.its_addresses {
        state::save_its_address(deps.storage, &chain, &address)?;
    }

    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg.ensure_permissions(deps.storage, &info.sender, match_gateway)? {
        ExecuteMsg::Execute(AxelarExecutableMsg {
            cc_id,
            source_address,
            payload,
        }) => execute::execute_message(deps, cc_id, source_address, payload)
            .change_context(Error::Execute),
        ExecuteMsg::SetItsAddress { chain, address } => {
            execute::set_its_address(deps, chain, address).change_context(Error::SetItsAddress)
        }
        ExecuteMsg::RemoveItsAddress { chain } => {
            execute::remove_its_address(deps, chain).change_context(Error::RemoveItsAddress)
        }
    }?
    .then(Ok)
}

fn match_gateway(storage: &dyn Storage, _: &ExecuteMsg) -> Result<Addr, Report<state::Error>> {
    Ok(state::load_config(storage)?.axelarnet_gateway)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    match msg {
        QueryMsg::ItsAddress { chain } => query::its_address(deps, chain)?,
        QueryMsg::AllItsAddresses => query::all_its_addresses(deps)?,
    }
    .then(Ok)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use axelar_wasm_std::permission_control::{self, Permission};
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::Addr;

    use crate::msg::InstantiateMsg;
    use crate::state;

    const GOVERNANCE: &str = "governance";
    const ADMIN: &str = "admin";

    #[test]
    fn instantiate() {
        let mut deps = mock_dependencies();

        let info = mock_info("sender", &[]);
        let env = mock_env();

        let its_addresses = vec![
            ("ethereum".parse().unwrap(), "eth-address".parse().unwrap()),
            ("optimism".parse().unwrap(), "op-address".parse().unwrap()),
        ]
        .into_iter()
        .collect::<HashMap<_, _>>();

        let msg = InstantiateMsg {
            governance_address: GOVERNANCE.parse().unwrap(),
            admin_address: ADMIN.parse().unwrap(),
            axelarnet_gateway_address: "gateway".into(),
            its_addresses: its_addresses.clone(),
        };

        let res = super::instantiate(deps.as_mut(), env, info, msg);
        assert!(res.is_ok());
        assert_eq!(0, res.unwrap().messages.len());

        assert_eq!(
            permission_control::sender_role(deps.as_ref().storage, &Addr::unchecked(ADMIN))
                .unwrap(),
            Permission::Admin.into()
        );

        assert_eq!(
            permission_control::sender_role(deps.as_ref().storage, &Addr::unchecked(GOVERNANCE))
                .unwrap(),
            Permission::Governance.into()
        );

        let stored_its_addresses = state::load_all_its_addresses(deps.as_mut().storage).unwrap();
        assert_eq!(stored_its_addresses, its_addresses);
    }
}
