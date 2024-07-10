use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{Config, CONFIG};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response};

use crate::error::ContractError;
use crate::execute;
use crate::query;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::ContractError> {
    // any version checks should be done before here

    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

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
        ExecuteMsg::SetActiveVerifiers { verifiers } => {
            execute::set_active_verifier_set(deps, info, verifiers)
        }
    }
    .map_err(axelar_wasm_std::ContractError::from)
}

#[cfg_attr(not(feature = "library"), entry_point)]
#[allow(dead_code)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    match msg {
        QueryMsg::ReadyToUnbond { worker_address } => to_json_binary(
            &query::check_verifier_ready_to_unbond(deps, worker_address)?,
        )
        .map_err(|err| err.into()),
    }
}

#[cfg(test)]
mod tests {

    use crate::error::ContractError;
    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{Addr, Empty, OwnedDeps};
    use router_api::ChainName;

    use super::*;

    struct TestSetup {
        deps: OwnedDeps<MockStorage, MockApi, MockQuerier, Empty>,
        env: Env,
        prover: Addr,
        chain_name: ChainName,
    }

    fn setup(governance: &str) -> TestSetup {
        let mut deps = mock_dependencies();
        let info = mock_info("instantiator", &[]);
        let env = mock_env();

        let instantiate_msg = InstantiateMsg {
            governance_address: governance.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), instantiate_msg);
        assert!(res.is_ok());

        let eth_prover = Addr::unchecked("eth_prover");
        let eth: ChainName = "Ethereum".to_string().try_into().unwrap();

        TestSetup {
            deps,
            env,
            prover: eth_prover,
            chain_name: eth,
        }
    }

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn test_instantiation() {
        let governance = "governance_for_coordinator";
        let test_setup = setup(governance);

        let config = CONFIG.load(test_setup.deps.as_ref().storage).unwrap();
        assert_eq!(config.governance, governance);
    }

    #[test]
    fn migrate_sets_contract_version() {
        let mut deps = mock_dependencies();

        migrate(deps.as_mut(), mock_env(), Empty {}).unwrap();

        let contract_version = cw2::get_contract_version(deps.as_mut().storage).unwrap();
        assert_eq!(contract_version.contract, "coordinator");
        assert_eq!(contract_version.version, CONTRACT_VERSION);
    }

    #[test]
    fn add_prover_from_governance_succeeds() {
        let governance = "governance_for_coordinator";
        let mut test_setup = setup(governance);

        let _res = execute(
            test_setup.deps.as_mut(),
            test_setup.env,
            mock_info(governance, &[]),
            ExecuteMsg::RegisterProverContract {
                chain_name: test_setup.chain_name.clone(),
                new_prover_addr: test_setup.prover.clone(),
            },
        )
        .unwrap();

        let chain_provers =
            query::prover(test_setup.deps.as_ref(), test_setup.chain_name.clone()).unwrap();
        assert_eq!(chain_provers, test_setup.prover);
    }

    #[test]
    fn add_prover_from_random_address_fails() {
        let governance = "governance_for_coordinator";
        let mut test_setup = setup(governance);

        let res = execute(
            test_setup.deps.as_mut(),
            test_setup.env,
            mock_info("random_address", &[]),
            ExecuteMsg::RegisterProverContract {
                chain_name: test_setup.chain_name.clone(),
                new_prover_addr: test_setup.prover.clone(),
            },
        );
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::ContractError::from(ContractError::Unauthorized).to_string()
        );
    }
}
