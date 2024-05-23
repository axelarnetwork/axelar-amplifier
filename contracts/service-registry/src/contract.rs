#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Addr, BankMsg, Binary, Coin, Deps, DepsMut, Empty, Env, MessageInfo, Order,
    QueryRequest, Response, Uint128, WasmQuery,
};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{AuthorizationState, BondingState, Config, Service, Worker, CONFIG, SERVICES};

mod execute;
mod query;

const CONTRACT_NAME: &str = "crates.io:service-registry";
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
            governance: deps.api.addr_validate(&msg.governance_account)?,
        },
    )?;
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    match msg {
        ExecuteMsg::RegisterService {
            service_name,
            coordinator_contract,
            min_num_workers,
            max_num_workers,
            min_worker_bond,
            bond_denom,
            unbonding_period_days,
            description,
        } => {
            execute::require_governance(&deps, info)?;
            execute::register_service(
                deps,
                service_name,
                coordinator_contract,
                min_num_workers,
                max_num_workers,
                min_worker_bond,
                bond_denom,
                unbonding_period_days,
                description,
            )
        }
        ExecuteMsg::AuthorizeWorkers {
            workers,
            service_name,
        } => {
            execute::require_governance(&deps, info)?;
            let workers = workers
                .into_iter()
                .map(|worker| deps.api.addr_validate(&worker))
                .collect::<Result<Vec<_>, _>>()?;
            execute::update_worker_authorization_status(
                deps,
                workers,
                service_name,
                AuthorizationState::Authorized,
            )
        }
        ExecuteMsg::UnauthorizeWorkers {
            workers,
            service_name,
        } => {
            execute::require_governance(&deps, info)?;
            let workers = workers
                .into_iter()
                .map(|worker| deps.api.addr_validate(&worker))
                .collect::<Result<Vec<_>, _>>()?;
            execute::update_worker_authorization_status(
                deps,
                workers,
                service_name,
                AuthorizationState::NotAuthorized,
            )
        }
        ExecuteMsg::JailWorkers {
            workers,
            service_name,
        } => {
            execute::require_governance(&deps, info)?;
            let workers = workers
                .into_iter()
                .map(|worker| deps.api.addr_validate(&worker))
                .collect::<Result<Vec<_>, _>>()?;
            execute::update_worker_authorization_status(
                deps,
                workers,
                service_name,
                AuthorizationState::Jailed,
            )
        }
        ExecuteMsg::RegisterChainSupport {
            service_name,
            chains,
        } => execute::register_chains_support(deps, info, service_name, chains),
        ExecuteMsg::DeregisterChainSupport {
            service_name,
            chains,
        } => execute::deregister_chains_support(deps, info, service_name, chains),
        ExecuteMsg::BondWorker { service_name } => execute::bond_worker(deps, info, service_name),
        ExecuteMsg::UnbondWorker { service_name } => {
            execute::unbond_worker(deps, env, info, service_name)
        }
        ExecuteMsg::ClaimStake { service_name } => {
            execute::claim_stake(deps, env, info, service_name)
        }
    }
    .map_err(axelar_wasm_std::ContractError::from)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    match msg {
        QueryMsg::GetActiveWorkers {
            service_name,
            chain_name,
        } => to_json_binary(&query::get_active_workers(deps, service_name, chain_name)?)
            .map_err(|err| err.into()),
        QueryMsg::GetWorker {
            service_name,
            worker,
        } => to_json_binary(&query::get_worker(deps, service_name, worker)?)
            .map_err(|err| err.into()),
        QueryMsg::GetService { service_name } => {
            to_json_binary(&query::get_service(deps, service_name)?).map_err(|err| err.into())
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use cosmwasm_std::{
        coins, from_json,
        testing::{mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage},
        CosmosMsg, Empty, OwnedDeps, StdResult,
    };
    use router_api::ChainName;

    use crate::state::{WeightedWorker, WORKER_WEIGHT};

    use super::*;

    const GOVERNANCE_ADDRESS: &str = "governance";
    const UNAUTHORIZED_ADDRESS: &str = "unauthorized";
    const COORDINATOR_ADDRESS: &str = "coordinator_address";
    const WORKER_ADDRESS: &str = "worker";
    const AXL_DENOMINATION: &str = "uaxl";

    fn setup() -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = mock_dependencies();

        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("instantiator", &[]),
            InstantiateMsg {
                governance_account: GOVERNANCE_ADDRESS.to_string(),
            },
        )
        .unwrap();

        deps.querier.update_wasm(move |wq| match wq {
            WasmQuery::Smart { contract_addr, .. } if contract_addr == COORDINATOR_ADDRESS => {
                Ok(to_json_binary(&true).into()).into()
            }
            _ => panic!("no mock for this query"),
        });

        deps
    }

    pub fn assert_contract_err_strings_equal(
        actual: impl Into<axelar_wasm_std::ContractError>,
        expected: impl Into<axelar_wasm_std::ContractError>,
    ) {
        assert_eq!(actual.into().to_string(), expected.into().to_string());
    }

    #[test]
    fn register_service() {
        let mut deps = setup();

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: "validators".into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_workers: 0,
                max_num_workers: Some(100),
                min_worker_bond: Uint128::zero(),
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(UNAUTHORIZED_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: "validators".into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_workers: 0,
                max_num_workers: Some(100),
                min_worker_bond: Uint128::zero(),
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        )
        .unwrap_err();
        assert_contract_err_strings_equal(err, ContractError::Unauthorized);
    }

    #[test]
    fn authorize_worker() {
        let mut deps = setup();

        let service_name = "validators";
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_workers: 0,
                max_num_workers: Some(100),
                min_worker_bond: Uint128::zero(),
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::AuthorizeWorkers {
                workers: vec![Addr::unchecked("worker").into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(UNAUTHORIZED_ADDRESS, &[]),
            ExecuteMsg::AuthorizeWorkers {
                workers: vec![Addr::unchecked("worker").into()],
                service_name: service_name.into(),
            },
        )
        .unwrap_err();
        assert_contract_err_strings_equal(err, ContractError::Unauthorized);
    }

    #[test]
    fn bond_worker() {
        let mut deps = setup();

        let service_name = "validators";
        let min_worker_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_workers: 0,
                max_num_workers: Some(100),
                min_worker_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::AuthorizeWorkers {
                workers: vec![WORKER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                WORKER_ADDRESS,
                &coins(min_worker_bond.u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondWorker {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());
    }

    #[test]
    fn register_chain_support() {
        let mut deps = setup();

        let service_name = "validators";
        let min_worker_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_workers: 0,
                max_num_workers: Some(100),
                min_worker_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::AuthorizeWorkers {
                workers: vec![WORKER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                WORKER_ADDRESS,
                &coins(min_worker_bond.u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondWorker {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = ChainName::from_str("ethereum").unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let workers: Vec<WeightedWorker> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetActiveWorkers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            workers,
            vec![WeightedWorker {
                worker_info: Worker {
                    address: Addr::unchecked(WORKER_ADDRESS),
                    bonding_state: BondingState::Bonded {
                        amount: min_worker_bond
                    },
                    authorization_state: AuthorizationState::Authorized,
                    service_name: service_name.into()
                },
                weight: WORKER_WEIGHT
            }]
        );

        let workers: Vec<WeightedWorker> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetActiveWorkers {
                    service_name: service_name.into(),
                    chain_name: ChainName::from_str("random chain").unwrap(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(workers, vec![]);
    }

    /// If a bonded and authorized worker deregisters support for a chain they previously registered support for,
    /// that worker should no longer be part of the active worker set for that chain
    #[test]
    fn register_and_deregister_support_for_single_chain() {
        let mut deps = setup();

        let service_name = "validators";
        let min_worker_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_workers: 0,
                max_num_workers: Some(100),
                min_worker_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::AuthorizeWorkers {
                workers: vec![WORKER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                WORKER_ADDRESS,
                &coins(min_worker_bond.u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondWorker {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = ChainName::from_str("ethereum").unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        // Deregister chain support
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let workers: Vec<WeightedWorker> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetActiveWorkers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(workers, vec![]);
    }

    /// Same setting and goal as register_and_deregister_support_for_single_chain() but for multiple chains.
    #[test]
    fn register_and_deregister_support_for_multiple_chains() {
        let mut deps = setup();

        let service_name = "validators";
        let min_worker_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_workers: 0,
                max_num_workers: Some(100),
                min_worker_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::AuthorizeWorkers {
                workers: vec![WORKER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                WORKER_ADDRESS,
                &coins(min_worker_bond.u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondWorker {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chains = vec![
            ChainName::from_str("ethereum").unwrap(),
            ChainName::from_str("binance").unwrap(),
            ChainName::from_str("avalanche").unwrap(),
        ];

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: chains.clone(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: chains.clone(),
            },
        );
        assert!(res.is_ok());

        for chain in chains {
            let workers: Vec<WeightedWorker> = from_json(
                &query(
                    deps.as_ref(),
                    mock_env(),
                    QueryMsg::GetActiveWorkers {
                        service_name: service_name.into(),
                        chain_name: chain,
                    },
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(workers, vec![]);
        }
    }

    /// If a bonded and authorized worker deregisters support for the first chain among multiple chains,
    /// they should remain part of the active worker set for all chains except the first one.
    #[test]
    fn register_for_multiple_chains_deregister_for_first_one() {
        let mut deps = setup();

        let service_name = "validators";
        let min_worker_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_workers: 0,
                max_num_workers: Some(100),
                min_worker_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::AuthorizeWorkers {
                workers: vec![WORKER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                WORKER_ADDRESS,
                &coins(min_worker_bond.u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondWorker {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chains = vec![
            ChainName::from_str("ethereum").unwrap(),
            ChainName::from_str("binance").unwrap(),
            ChainName::from_str("avalanche").unwrap(),
        ];

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: chains.clone(),
            },
        );
        assert!(res.is_ok());

        // Deregister only the first chain
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chains[0].clone()],
            },
        );
        assert!(res.is_ok());

        // Verify that worker is not associated with the deregistered chain
        let deregistered_chain = chains[0].clone();
        let workers: Vec<WeightedWorker> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetActiveWorkers {
                    service_name: service_name.into(),
                    chain_name: deregistered_chain,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(workers, vec![]);

        // Verify that worker is still associated with other chains
        for chain in chains.iter().skip(1) {
            let workers: Vec<WeightedWorker> = from_json(
                &query(
                    deps.as_ref(),
                    mock_env(),
                    QueryMsg::GetActiveWorkers {
                        service_name: service_name.into(),
                        chain_name: chain.clone(),
                    },
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(
                workers,
                vec![WeightedWorker {
                    worker_info: Worker {
                        address: Addr::unchecked(WORKER_ADDRESS),
                        bonding_state: BondingState::Bonded {
                            amount: min_worker_bond
                        },
                        authorization_state: AuthorizationState::Authorized,
                        service_name: service_name.into()
                    },
                    weight: WORKER_WEIGHT
                }]
            );
        }
    }

    /// If a bonded and authorized worker registers support for one chain and later deregisters support for another chain,
    /// the active worker set for the original chain should remain unaffected by the deregistration.
    #[test]
    fn register_support_for_a_chain_deregister_support_for_another_chain() {
        let mut deps = setup();

        let service_name = "validators";
        let min_worker_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_workers: 0,
                max_num_workers: Some(100),
                min_worker_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::AuthorizeWorkers {
                workers: vec![WORKER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                WORKER_ADDRESS,
                &coins(min_worker_bond.u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondWorker {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = ChainName::from_str("ethereum").unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let second_chain_name = ChainName::from_str("avalanche").unwrap();
        // Deregister support for another chain
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![second_chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let workers: Vec<WeightedWorker> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetActiveWorkers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            workers,
            vec![WeightedWorker {
                worker_info: Worker {
                    address: Addr::unchecked(WORKER_ADDRESS),
                    bonding_state: BondingState::Bonded {
                        amount: min_worker_bond
                    },
                    authorization_state: AuthorizationState::Authorized,
                    service_name: service_name.into()
                },
                weight: WORKER_WEIGHT
            }]
        );
    }

    /// If a bonded and authorized worker registers, deregisters, and again registers their support for a single chain,
    /// the active worker set of that chain should include the worker.
    #[test]
    fn register_deregister_register_support_for_single_chain() {
        let mut deps = setup();

        let service_name = "validators";
        let min_worker_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_workers: 0,
                max_num_workers: Some(100),
                min_worker_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::AuthorizeWorkers {
                workers: vec![WORKER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                WORKER_ADDRESS,
                &coins(min_worker_bond.u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondWorker {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = ChainName::from_str("ethereum").unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        // Second support declaration
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let workers: Vec<WeightedWorker> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetActiveWorkers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            workers,
            vec![WeightedWorker {
                worker_info: Worker {
                    address: Addr::unchecked(WORKER_ADDRESS),
                    bonding_state: BondingState::Bonded {
                        amount: min_worker_bond
                    },
                    authorization_state: AuthorizationState::Authorized,
                    service_name: service_name.into()
                },
                weight: WORKER_WEIGHT
            }]
        );
    }

    /// If a bonded and authorized worker deregisters their support for a chain they have not previously registered
    /// support for, the call should be ignored and the active worker set of the chain should be intact.
    #[test]
    fn deregister_previously_unsupported_single_chain() {
        let mut deps = setup();

        let service_name = "validators";
        let min_worker_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_workers: 0,
                max_num_workers: Some(100),
                min_worker_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::AuthorizeWorkers {
                workers: vec![WORKER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                WORKER_ADDRESS,
                &coins(min_worker_bond.u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondWorker {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = ChainName::from_str("ethereum").unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let workers: Vec<WeightedWorker> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetActiveWorkers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(workers, vec![])
    }

    /// If an unbonded but authorized worker deregisters support for a chain they previously registered support for,
    /// that worker should not be part of the active worker set for that chain.
    #[test]
    fn register_and_deregister_support_for_single_chain_unbonded() {
        let mut deps = setup();

        let service_name = "validators";
        let min_worker_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_workers: 0,
                max_num_workers: Some(100),
                min_worker_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::AuthorizeWorkers {
                workers: vec![WORKER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = ChainName::from_str("ethereum").unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let workers: Vec<WeightedWorker> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetActiveWorkers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(workers, vec![]);
    }

    /// If a worker that is not part of a service deregisters support for a chain from that specific service,
    /// process should return a contract error of type WorkerNotFound.
    #[test]
    fn deregister_from_unregistered_worker_single_chain() {
        let mut deps = setup();

        let service_name = "validators";
        let min_worker_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_workers: 0,
                max_num_workers: Some(100),
                min_worker_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = ChainName::from_str("ethereum").unwrap();
        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        )
        .unwrap_err();

        assert_contract_err_strings_equal(err, ContractError::WorkerNotFound);

        let workers: Vec<WeightedWorker> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetActiveWorkers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(workers, vec![]);
    }

    /// If a worker deregisters support for a chain of an unregistered service,
    /// process should return a contract error of type ServiceNotFound.
    #[test]
    fn deregister_single_chain_for_nonexistent_service() {
        let mut deps = setup();

        let service_name = "validators";
        let chain_name = ChainName::from_str("ethereum").unwrap();
        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        )
        .unwrap_err();

        assert_contract_err_strings_equal(err, ContractError::ServiceNotFound);
    }

    #[test]
    fn unbond_worker() {
        let mut deps = setup();

        let service_name = "validators";
        let min_worker_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_workers: 0,
                max_num_workers: Some(100),
                min_worker_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::AuthorizeWorkers {
                workers: vec![WORKER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                WORKER_ADDRESS,
                &coins(min_worker_bond.u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondWorker {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = ChainName::from_str("ethereum").unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::UnbondWorker {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let workers: Vec<WeightedWorker> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetActiveWorkers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(workers, vec![])
    }

    #[test]
    fn bond_wrong_denom() {
        let mut deps = setup();

        let service_name = "validators";
        let min_worker_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_workers: 0,
                max_num_workers: Some(100),
                min_worker_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &coins(min_worker_bond.u128(), "funnydenom")),
            ExecuteMsg::BondWorker {
                service_name: service_name.into(),
            },
        )
        .unwrap_err();

        assert_contract_err_strings_equal(err, ContractError::WrongDenom);
    }

    #[test]
    fn bond_but_not_authorized() {
        let mut deps = setup();

        let service_name = "validators";
        let min_worker_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_workers: 0,
                max_num_workers: Some(100),
                min_worker_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                WORKER_ADDRESS,
                &coins(min_worker_bond.u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondWorker {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = ChainName::from_str("ethereum").unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let workers: Vec<WeightedWorker> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetActiveWorkers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(workers, vec![])
    }

    #[test]
    fn bond_but_not_enough() {
        let mut deps = setup();

        let service_name = "validators";
        let min_worker_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_workers: 0,
                max_num_workers: Some(100),
                min_worker_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::AuthorizeWorkers {
                workers: vec![WORKER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                WORKER_ADDRESS,
                &coins(min_worker_bond.u128() / 2, AXL_DENOMINATION),
            ),
            ExecuteMsg::BondWorker {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = ChainName::from_str("ethereum").unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let workers: Vec<WeightedWorker> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetActiveWorkers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(workers, vec![])
    }

    #[test]
    fn bond_before_authorize() {
        let mut deps = setup();

        let service_name = "validators";
        let min_worker_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_workers: 0,
                max_num_workers: Some(100),
                min_worker_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                WORKER_ADDRESS,
                &coins(min_worker_bond.u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondWorker {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::AuthorizeWorkers {
                workers: vec![WORKER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = ChainName::from_str("ethereum").unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let workers: Vec<WeightedWorker> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetActiveWorkers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            workers,
            vec![WeightedWorker {
                worker_info: Worker {
                    address: Addr::unchecked(WORKER_ADDRESS),
                    bonding_state: BondingState::Bonded {
                        amount: min_worker_bond
                    },
                    authorization_state: AuthorizationState::Authorized,
                    service_name: service_name.into()
                },
                weight: WORKER_WEIGHT
            }]
        );
    }

    #[test]
    fn unbond_then_rebond() {
        let mut deps = setup();

        let service_name = "validators";
        let min_worker_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_workers: 0,
                max_num_workers: Some(100),
                min_worker_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::AuthorizeWorkers {
                workers: vec![WORKER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                WORKER_ADDRESS,
                &coins(min_worker_bond.u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondWorker {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = ChainName::from_str("ethereum").unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::UnbondWorker {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::BondWorker {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let workers: Vec<WeightedWorker> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetActiveWorkers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            workers,
            vec![WeightedWorker {
                worker_info: Worker {
                    address: Addr::unchecked(WORKER_ADDRESS),
                    bonding_state: BondingState::Bonded {
                        amount: min_worker_bond
                    },
                    authorization_state: AuthorizationState::Authorized,
                    service_name: service_name.into()
                },
                weight: WORKER_WEIGHT
            }]
        );
    }

    #[test]
    fn unbonding_period() {
        let mut deps = setup();

        let min_worker_bond = Uint128::new(100);
        let service_name = "validators";
        let unbonding_period_days = 1;

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_workers: 0,
                max_num_workers: Some(100),
                min_worker_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::AuthorizeWorkers {
                workers: vec![WORKER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                WORKER_ADDRESS,
                &coins(min_worker_bond.u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondWorker {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = ChainName::from_str("ethereum").unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name],
            },
        );
        assert!(res.is_ok());

        let mut unbond_request_env = mock_env();
        unbond_request_env.block.time = unbond_request_env.block.time.plus_days(1);

        let res = execute(
            deps.as_mut(),
            unbond_request_env.clone(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::UnbondWorker {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), Response::new());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::ClaimStake {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::ContractError::from(ContractError::InvalidBondingState(
                BondingState::Unbonding {
                    unbonded_at: unbond_request_env.block.time,
                    amount: min_worker_bond,
                }
            ))
            .to_string()
        );

        let mut after_unbond_period_env = mock_env();
        after_unbond_period_env.block.time = unbond_request_env
            .block
            .time
            .plus_days((unbonding_period_days + 1).into());

        let res = execute(
            deps.as_mut(),
            after_unbond_period_env,
            mock_info(WORKER_ADDRESS, &[]),
            ExecuteMsg::ClaimStake {
                service_name: service_name.into(),
            },
        )
        .unwrap();
        assert_eq!(res.messages.len(), 1);
        assert_eq!(
            res.messages[0].msg,
            CosmosMsg::Bank(BankMsg::Send {
                to_address: WORKER_ADDRESS.into(),
                amount: coins(min_worker_bond.u128(), AXL_DENOMINATION)
            })
        )
    }

    #[test]
    fn get_active_workers_should_not_return_less_than_min() {
        let mut deps = setup();

        let workers = vec![Addr::unchecked("worker1"), Addr::unchecked("worker2")];
        let min_num_workers = workers.len() as u16;

        let service_name = "validators";
        let min_worker_bond = Uint128::new(100);
        let _ = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_workers,
                max_num_workers: Some(100),
                min_worker_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        )
        .unwrap();

        let _ = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::AuthorizeWorkers {
                workers: workers.iter().map(|w| w.into()).collect(),
                service_name: service_name.into(),
            },
        )
        .unwrap();

        let chain_name = ChainName::from_str("ethereum").unwrap();

        for worker in &workers {
            // should return err until all workers are registered
            let res = query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetActiveWorkers {
                    service_name: service_name.into(),
                    chain_name: chain_name.clone(),
                },
            );
            assert!(res.is_err());

            let _ = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(
                    worker.as_str(),
                    &coins(min_worker_bond.u128(), AXL_DENOMINATION),
                ),
                ExecuteMsg::BondWorker {
                    service_name: service_name.into(),
                },
            )
            .unwrap();

            let _ = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(worker.as_str(), &[]),
                ExecuteMsg::RegisterChainSupport {
                    service_name: service_name.into(),
                    chains: vec![chain_name.clone()],
                },
            )
            .unwrap();
        }

        // all workers registered, should not return err now
        let res: StdResult<Vec<WeightedWorker>> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetActiveWorkers {
                    service_name: service_name.into(),
                    chain_name: chain_name.clone(),
                },
            )
            .unwrap(),
        );
        assert!(res.is_ok());

        // remove one, should return err again
        let _ = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(workers[0].as_str(), &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        )
        .unwrap();
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name: chain_name.clone(),
            },
        );
        assert!(res.is_err());
    }

    #[test]
    fn jail_worker() {
        let mut deps = setup();

        // register a service
        let service_name = "validators";
        let min_worker_bond = Uint128::new(100);
        let unbonding_period_days = 10;
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_workers: 0,
                max_num_workers: Some(100),
                min_worker_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        // given a bonded worker
        let worker1 = Addr::unchecked("worker-1");
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                worker1.as_str(),
                &coins(min_worker_bond.u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondWorker {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        // when worker is jailed
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::JailWorkers {
                workers: vec![worker1.clone().into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        // worker cannot unbond
        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(worker1.as_str(), &[]),
            ExecuteMsg::UnbondWorker {
                service_name: service_name.into(),
            },
        )
        .unwrap_err();
        assert_contract_err_strings_equal(err, ContractError::WorkerJailed);

        // given a worker passed unbonding period
        let worker2 = Addr::unchecked("worker-2");

        // bond worker
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                worker2.as_str(),
                &coins(min_worker_bond.u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondWorker {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let mut unbond_request_env = mock_env();
        unbond_request_env.block.time = unbond_request_env.block.time.plus_days(1);

        // unbond worker
        let res = execute(
            deps.as_mut(),
            unbond_request_env.clone(),
            mock_info(worker2.as_str(), &[]),
            ExecuteMsg::UnbondWorker {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());
        let worker: Worker = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetWorker {
                    service_name: service_name.into(),
                    worker: worker2.to_string(),
                },
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            worker.bonding_state,
            BondingState::Unbonding {
                amount: min_worker_bond,
                unbonded_at: unbond_request_env.block.time,
            }
        );

        // when worker is jailed
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::JailWorkers {
                workers: vec![worker2.clone().into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        // and unbonding period has passed
        let mut after_unbond_period_env = mock_env();
        after_unbond_period_env.block.time = unbond_request_env
            .block
            .time
            .plus_days((unbonding_period_days + 1).into());

        // worker cannot claim stake
        let err = execute(
            deps.as_mut(),
            after_unbond_period_env,
            mock_info(worker2.as_str(), &[]),
            ExecuteMsg::ClaimStake {
                service_name: service_name.into(),
            },
        )
        .unwrap_err();
        assert_contract_err_strings_equal(err, ContractError::WorkerJailed);
    }
}
