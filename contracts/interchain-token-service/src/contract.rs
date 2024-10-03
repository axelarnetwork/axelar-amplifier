use std::fmt::Debug;

use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::{address, permission_control, FnExt, IntoContractError};
use axelarnet_gateway::AxelarExecutableMsg;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Addr, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response, Storage};
use error_stack::{Report, ResultExt};

use crate::events::Event;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state;
use crate::state::Config;

mod execute;
mod query;

pub use execute::Error as ExecuteError;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("failed to execute a cross-chain message")]
    Execute,
    #[error("failed to register an its edge contract")]
    RegisterItsContract,
    #[error("failed to deregsiter an its edge contract")]
    DeregisterItsContract,
    #[error("failed to register gateway token")]
    RegisterGatewayToken,
    #[error("failed to query its address")]
    QueryItsContract,
    #[error("failed to query all its addresses")]
    QueryAllItsContracts,
    #[error("failed to query gateway tokens")]
    QueryGatewayTokens,
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

    let admin = address::validate_cosmwasm_address(deps.api, &msg.admin_address)?;
    let governance = address::validate_cosmwasm_address(deps.api, &msg.governance_address)?;

    permission_control::set_admin(deps.storage, &admin)?;
    permission_control::set_governance(deps.storage, &governance)?;

    let axelarnet_gateway =
        address::validate_cosmwasm_address(deps.api, &msg.axelarnet_gateway_address)?;

    state::save_config(deps.storage, &Config { axelarnet_gateway })?;

    for (chain, address) in msg.its_contracts.iter() {
        state::save_its_contract(deps.storage, chain, address)?;
    }

    Ok(Response::new().add_events(
        msg.its_contracts
            .into_iter()
            .map(|(chain, address)| Event::ItsContractRegistered { chain, address }.into()),
    ))
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
        ExecuteMsg::RegisterItsContract { chain, address } => {
            execute::register_its_contract(deps, chain, address)
                .change_context(Error::RegisterItsContract)
        }
        ExecuteMsg::DeregisterItsContract { chain } => {
            execute::deregister_its_contract(deps, chain)
                .change_context(Error::DeregisterItsContract)
        }
        ExecuteMsg::RegisterGatewayToken {
            denom,
            source_chain,
        } => execute::register_gateway_token(deps, denom, source_chain)
            .change_context(Error::RegisterGatewayToken),
    }?
    .then(Ok)
}

fn match_gateway(storage: &dyn Storage, _: &ExecuteMsg) -> Result<Addr, Report<Error>> {
    Ok(state::load_config(storage).axelarnet_gateway)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    match msg {
        QueryMsg::ItsContract { chain } => {
            query::its_contracts(deps, chain).change_context(Error::QueryItsContract)
        }
        QueryMsg::AllItsContracts => {
            query::all_its_contracts(deps).change_context(Error::QueryAllItsContracts)
        }
        QueryMsg::GatewayTokens => {
            query::gateway_tokens(deps).change_context(Error::QueryGatewayTokens)
        }
    }?
    .then(Ok)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use axelar_wasm_std::nonempty;
    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{from_json, to_json_binary, OwnedDeps, WasmQuery};
    use router_api::{ChainName, ChainNameRaw};

    use super::{execute, instantiate};
    use crate::contract::execute::gateway_token_id;
    use crate::contract::query;
    use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
    use crate::TokenId;
    const GOVERNANCE_ADDRESS: &str = "governance";
    const ADMIN_ADDRESS: &str = "admin";
    const AXELARNET_GATEWAY_ADDRESS: &str = "axelarnet-gateway";

    #[test]
    fn register_gateway_token_should_register_denom_and_token_id() {
        let mut deps = setup();
        let denom = "uaxl";
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterGatewayToken {
                denom: denom.try_into().unwrap(),
                source_chain: ChainNameRaw::try_from("axelar").unwrap(),
            },
        );
        assert!(res.is_ok());

        let tokens: HashMap<nonempty::String, TokenId> =
            from_json(query(deps.as_ref(), mock_env(), QueryMsg::GatewayTokens).unwrap()).unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(
            tokens,
            HashMap::from([(
                denom.try_into().unwrap(),
                gateway_token_id(&deps.as_mut(), denom).unwrap()
            )])
        );
    }

    fn setup() -> OwnedDeps<MockStorage, MockApi, MockQuerier> {
        let mut deps = mock_dependencies();

        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("instantiator", &[]),
            InstantiateMsg {
                governance_address: GOVERNANCE_ADDRESS.to_string(),
                admin_address: ADMIN_ADDRESS.to_string(),
                axelarnet_gateway_address: AXELARNET_GATEWAY_ADDRESS.to_string(),
                its_contracts: HashMap::new(),
            },
        )
        .unwrap();

        deps.querier.update_wasm(move |wq| match wq {
            WasmQuery::Smart { contract_addr, .. }
                if contract_addr == AXELARNET_GATEWAY_ADDRESS =>
            {
                Ok(to_json_binary(&ChainName::try_from("axelar").unwrap()).into()).into()
            }
            _ => panic!("no mock for this query"),
        });

        deps
    }
}
