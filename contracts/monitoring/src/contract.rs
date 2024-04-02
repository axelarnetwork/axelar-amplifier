use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{Config, CONFIG};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};

use crate::execute;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    CONFIG.save(
        deps.storage,
        &Config {
            governance: deps.api.addr_validate(&msg.governance_address)?,
        },
    )?;
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    match msg {
        ExecuteMsg::RegisterProverContract {
            chain_name,
            new_prover_addr,
        } => {
            execute::check_governance(&deps, info)?;
            execute::register_prover(deps, chain_name, new_prover_addr)
        }
    }
    .map_err(axelar_wasm_std::ContractError::from)
}

#[cfg_attr(not(feature = "library"), entry_point)]
#[allow(dead_code)]
pub fn query(_deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetActiveVerifiersForChain { chain: _ } => {
            todo!()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::error::ContractError;
    use crate::query;
    use connection_router_api::ChainName;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::Addr;

    use super::*;

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn test_instantiation() {
        let governance = "governance_for_monitoring";
        let mut deps = mock_dependencies();
        let info = mock_info("instantiator", &[]);
        let env = mock_env();

        let res = instantiate(
            deps.as_mut(),
            env,
            info,
            InstantiateMsg {
                governance_address: governance.to_string(),
            },
        );
        assert!(res.is_ok());

        let config = CONFIG.load(deps.as_ref().storage).unwrap();
        assert_eq!(config.governance, governance);
    }

    #[test]
    fn add_prover_from_goverance_succeeds() {
        let governance = "governance_for_monitoring";
        let mut deps = mock_dependencies();
        let info = mock_info("instantiator", &[]);
        let env = mock_env();

        let _ = instantiate(
            deps.as_mut(),
            env.clone(),
            info,
            InstantiateMsg {
                governance_address: governance.to_string(),
            },
        );

        let eth_prover = Addr::unchecked("eth_prover");
        let eth: ChainName = "Ethereum".to_string().try_into().unwrap();
        let msg = ExecuteMsg::RegisterProverContract {
            chain_name: eth.clone(),
            new_prover_addr: eth_prover.clone(),
        };
        let _res = execute(deps.as_mut(), mock_env(), mock_info(governance, &[]), msg).unwrap();
        let chain_provers = query::provers(deps.as_ref(), eth.clone()).unwrap();
        assert_eq!(chain_provers, vec![eth_prover]);
    }

    #[test]
    fn add_prover_from_random_address_fails() {
        let governance = "governance_for_monitoring";
        let mut deps = mock_dependencies();
        let info = mock_info("instantiator", &[]);
        let env = mock_env();

        let _ = instantiate(
            deps.as_mut(),
            env.clone(),
            info,
            InstantiateMsg {
                governance_address: governance.to_string(),
            },
        );

        let eth_prover = Addr::unchecked("eth_prover");
        let eth: ChainName = "Ethereum".to_string().try_into().unwrap();
        let msg = ExecuteMsg::RegisterProverContract {
            chain_name: eth.clone(),
            new_prover_addr: eth_prover.clone(),
        };
        let res = execute(
            deps.as_mut(),
            env.clone(),
            mock_info("random_address", &[]),
            msg,
        );
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::ContractError::from(ContractError::Unauthorized).to_string()
        );
    }
}
