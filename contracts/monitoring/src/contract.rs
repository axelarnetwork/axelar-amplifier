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
        ExecuteMsg::RegisterChainContracts {
            chain_name,
            verifier_contract,
            gateway_contract,
            prover_contract,
        } => {
            execute::check_governance(&deps, info)?;
            execute::register_chain_contracts(
                deps,
                chain_name,
                verifier_contract,
                gateway_contract,
                prover_contract,
            )
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
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};

    use super::*;

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn test_instantiation() {
        let governance = "governance_for_monitoring";
        let mut deps = mock_dependencies();
        let info = mock_info("instantiator", &[]);
        let env = mock_env();

        let msg = InstantiateMsg {
            governance_address: governance.to_string(),
        };

        let res = instantiate(deps.as_mut(), env, info, msg);
        assert!(res.is_ok());

        let config = CONFIG.load(deps.as_ref().storage).unwrap();
        assert_eq!(config.governance, governance);
    }
}
