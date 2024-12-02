mod execute;
mod migrations;
mod query;

use axelar_wasm_std::address::validate_cosmwasm_address;
use axelar_wasm_std::{address, permission_control, FnExt};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    ensure, to_json_binary, Addr, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response, Storage,
};
use cw2::VersionError;
use error_stack::report;
use itertools::Itertools;
use semver::{Version, VersionReq};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{is_prover_registered, Config, CONFIG};

pub const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
pub const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    let old_version = Version::parse(&cw2::get_contract_version(deps.storage)?.version)?;
    ensure!(
        old_version.major == 1 && old_version.minor == 1,
        report!(VersionError::WrongVersion {
            expected: "1.1.x".into(),
            found: old_version.to_string()
        })
    );

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
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let config = Config {
        service_registry: address::validate_cosmwasm_address(deps.api, &msg.service_registry)?,
    };
    CONFIG.save(deps.storage, &config)?;

    let governance = address::validate_cosmwasm_address(deps.api, &msg.governance_address)?;
    permission_control::set_governance(deps.storage, &governance)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    match msg.ensure_permissions(
        deps.storage,
        &info.sender,
        find_prover_address(&info.sender),
    )? {
        ExecuteMsg::RegisterProverContract {
            chain_name,
            new_prover_addr,
        } => {
            let new_prover_addr = validate_cosmwasm_address(deps.api, &new_prover_addr)?;
            execute::register_prover(deps, chain_name, new_prover_addr)
        }
        ExecuteMsg::SetActiveVerifiers { verifiers } => {
            let verifiers = verifiers
                .iter()
                .map(|v| validate_cosmwasm_address(deps.api, v))
                .try_collect()?;
            execute::set_active_verifier_set(deps, info, verifiers)
        }
    }?
    .then(Ok)
}

fn find_prover_address(
    sender: &Addr,
) -> impl FnOnce(&dyn Storage, &ExecuteMsg) -> error_stack::Result<Addr, ContractError> + '_ {
    |storage, _| {
        if is_prover_registered(storage, sender.clone())? {
            Ok(sender.clone())
        } else {
            Err(report!(ContractError::ProverNotRegistered))
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps,
    _env: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::error::ContractError> {
    match msg {
        QueryMsg::ReadyToUnbond {
            verifier_address: worker_address,
        } => {
            let worker_address = validate_cosmwasm_address(deps.api, &worker_address)?;
            to_json_binary(&query::check_verifier_ready_to_unbond(
                deps,
                worker_address,
            )?)?
        }
        QueryMsg::VerifierInfo {
            service_name,
            verifier,
        } => {
            let verifier_address = validate_cosmwasm_address(deps.api, &verifier)?;
            to_json_binary(&query::verifier_details_with_provers(
                deps,
                service_name,
                verifier_address,
            )?)?
        }
    }
    .then(Ok)
}

#[cfg(test)]
mod tests {

    use std::collections::HashSet;

    use axelar_wasm_std::permission_control::Permission;
    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{Addr, Empty, OwnedDeps};
    use router_api::ChainName;

    use super::*;
    use crate::state::load_prover_by_chain;

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
            service_registry: Addr::unchecked("random_service").to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), instantiate_msg);
        assert!(res.is_ok());

        let eth_prover = Addr::unchecked("eth_prover");
        let eth: ChainName = "Ethereum".parse().unwrap();

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
                new_prover_addr: test_setup.prover.to_string(),
            }
        )
        .is_err());

        assert!(execute(
            test_setup.deps.as_mut(),
            test_setup.env,
            mock_info(governance, &[]),
            ExecuteMsg::RegisterProverContract {
                chain_name: test_setup.chain_name.clone(),
                new_prover_addr: test_setup.prover.to_string(),
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
                new_prover_addr: test_setup.prover.to_string(),
            },
        )
        .unwrap();

        let chain_prover = load_prover_by_chain(
            test_setup.deps.as_ref().storage,
            test_setup.chain_name.clone(),
        );
        assert!(chain_prover.is_ok(), "{:?}", chain_prover);
        assert_eq!(chain_prover.unwrap(), test_setup.prover);
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
                new_prover_addr: test_setup.prover.to_string(),
            },
        );
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(
                permission_control::Error::PermissionDenied {
                    expected: Permission::Governance.into(),
                    actual: Permission::NoPrivilege.into()
                }
            )
            .to_string()
        );
    }

    #[test]
    fn set_active_verifiers_from_prover_succeeds() {
        let governance = "governance_for_coordinator";
        let mut test_setup = setup(governance);

        execute(
            test_setup.deps.as_mut(),
            test_setup.env.clone(),
            mock_info(governance, &[]),
            ExecuteMsg::RegisterProverContract {
                chain_name: test_setup.chain_name.clone(),
                new_prover_addr: test_setup.prover.to_string(),
            },
        )
        .unwrap();

        let res = execute(
            test_setup.deps.as_mut(),
            test_setup.env,
            mock_info(test_setup.prover.as_str(), &[]),
            ExecuteMsg::SetActiveVerifiers {
                verifiers: HashSet::new(),
            },
        );
        assert!(res.is_ok(), "{:?}", res);
    }

    #[test]
    fn set_active_verifiers_from_random_address_fails() {
        let governance = "governance_for_coordinator";
        let mut test_setup = setup(governance);

        let res = execute(
            test_setup.deps.as_mut(),
            test_setup.env,
            mock_info(test_setup.prover.as_str(), &[]),
            ExecuteMsg::SetActiveVerifiers {
                verifiers: HashSet::new(),
            },
        );
        assert!(res.unwrap_err().to_string().contains(
            &axelar_wasm_std::error::ContractError::from(
                permission_control::Error::WhitelistNotFound {
                    sender: test_setup.prover
                }
            )
            .to_string()
        ));
    }

    #[test]
    fn migrate_sets_contract_version() {
        let governance = "governance_for_coordinator";
        let mut test_setup = setup(governance);

        migrate(test_setup.deps.as_mut(), mock_env(), Empty {}).unwrap();

        let contract_version = cw2::get_contract_version(test_setup.deps.as_mut().storage).unwrap();
        assert_eq!(contract_version.contract, CONTRACT_NAME);
        assert_eq!(contract_version.version, CONTRACT_VERSION);
    }
}
