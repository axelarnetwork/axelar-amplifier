mod execute;
mod query;

mod migrations;
use crate::contract::migrations::v0_2_0;
use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use axelar_wasm_std::permission_control;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response};

pub const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
pub const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::ContractError> {
    v0_2_0::migrate(deps.storage)?;

    // this needs to be the last thing to do during migration,
    // because previous migration steps should check the old version
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

    let governance = deps.api.addr_validate(&msg.governance_address)?;
    permission_control::set_governance(deps.storage, &governance)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    match msg.ensure_permissions(deps.storage, &info.sender)? {
        ExecuteMsg::RegisterProverContract {
            chain_name,
            new_prover_addr,
        } => execute::register_prover(deps, chain_name, new_prover_addr),
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

    use super::*;
    use crate::error::ContractError;
    use crate::state::PROVER_PER_CHAIN;
    use axelar_wasm_std::permission_control::Permission;
    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{Addr, Empty, OwnedDeps};
    use router_api::ChainName;

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
        let mut test_setup = setup(governance);

        assert!(execute(
            test_setup.deps.as_mut(),
            test_setup.env.clone(),
            mock_info("not_governance", &[]),
            ExecuteMsg::RegisterProverContract {
                chain_name: test_setup.chain_name.clone(),
                new_prover_addr: test_setup.prover.clone(),
            }
        )
        .is_err());

        assert!(execute(
            test_setup.deps.as_mut(),
            test_setup.env,
            mock_info(governance, &[]),
            ExecuteMsg::RegisterProverContract {
                chain_name: test_setup.chain_name.clone(),
                new_prover_addr: test_setup.prover.clone(),
            }
        )
        .is_ok());
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
            prover(test_setup.deps.as_ref(), test_setup.chain_name.clone()).unwrap();
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
            axelar_wasm_std::ContractError::from(permission_control::Error::PermissionDenied {
                expected: Permission::Governance.into(),
                actual: Permission::NoPrivilege.into()
            })
            .to_string()
        );
    }

    fn prover(deps: Deps, chain_name: ChainName) -> Result<Addr, ContractError> {
        PROVER_PER_CHAIN
            .may_load(deps.storage, chain_name.clone())?
            .ok_or(ContractError::NoProversRegisteredForChain(chain_name))
    }
}
