use axelar_wasm_std::{address, permission_control, FnExt};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Addr, BankMsg, Binary, Coin, Deps, DepsMut, Empty, Env, MessageInfo, Order,
    QueryRequest, Response, Storage, WasmQuery,
};
use error_stack::{bail, Report, ResultExt};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{AuthorizationState, BondingState, Service, Verifier, SERVICES, VERIFIERS};

mod execute;
mod migrations;
mod query;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let governance = address::validate_cosmwasm_address(deps.api, &msg.governance_account)?;
    permission_control::set_governance(deps.storage, &governance)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    match msg.ensure_permissions(deps.storage, &info.sender, match_verifier(&info.sender))? {
        ExecuteMsg::RegisterService {
            service_name,
            coordinator_contract,
            min_num_verifiers,
            max_num_verifiers,
            min_verifier_bond,
            bond_denom,
            unbonding_period_days,
            description,
        } => execute::register_service(
            deps,
            service_name,
            coordinator_contract,
            min_num_verifiers,
            max_num_verifiers,
            min_verifier_bond,
            bond_denom,
            unbonding_period_days,
            description,
        ),
        ExecuteMsg::AuthorizeVerifiers {
            verifiers,
            service_name,
        } => {
            let verifiers = verifiers
                .into_iter()
                .map(|verifier| address::validate_cosmwasm_address(deps.api, &verifier))
                .collect::<Result<Vec<_>, _>>()?;
            execute::update_verifier_authorization_status(
                deps,
                verifiers,
                service_name,
                AuthorizationState::Authorized,
            )
        }
        ExecuteMsg::UnauthorizeVerifiers {
            verifiers,
            service_name,
        } => {
            let verifiers = verifiers
                .into_iter()
                .map(|verifier| address::validate_cosmwasm_address(deps.api, &verifier))
                .collect::<Result<Vec<_>, _>>()?;
            execute::update_verifier_authorization_status(
                deps,
                verifiers,
                service_name,
                AuthorizationState::NotAuthorized,
            )
        }
        ExecuteMsg::JailVerifiers {
            verifiers,
            service_name,
        } => {
            let verifiers = verifiers
                .into_iter()
                .map(|verifier| address::validate_cosmwasm_address(deps.api, &verifier))
                .collect::<Result<Vec<_>, _>>()?;
            execute::update_verifier_authorization_status(
                deps,
                verifiers,
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
        ExecuteMsg::BondVerifier { service_name } => {
            execute::bond_verifier(deps, info, service_name)
        }
        ExecuteMsg::UnbondVerifier { service_name } => {
            execute::unbond_verifier(deps, env, info, service_name)
        }
        ExecuteMsg::ClaimStake { service_name } => {
            execute::claim_stake(deps, env, info, service_name)
        }
    }?
    .then(Ok)
}

fn match_verifier(
    sender: &Addr,
) -> impl FnOnce(&dyn Storage, &ExecuteMsg) -> Result<Addr, Report<permission_control::Error>> + '_
{
    |storage: &dyn Storage, msg: &ExecuteMsg| {
        let service_name = match msg {
            ExecuteMsg::RegisterChainSupport { service_name, .. }
            | ExecuteMsg::DeregisterChainSupport { service_name, .. } => service_name,
            _ => bail!(permission_control::Error::WrongVariant),
        };
        VERIFIERS
            .load(storage, (service_name, sender))
            .map(|verifier| verifier.address)
            .change_context(permission_control::Error::Unauthorized)
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps,
    _env: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::error::ContractError> {
    match msg {
        QueryMsg::ActiveVerifiers {
            service_name,
            chain_name,
        } => to_json_binary(&query::active_verifiers(deps, service_name, chain_name)?)
            .map_err(|err| err.into()),
        QueryMsg::Verifier {
            service_name,
            verifier,
        } => to_json_binary(&query::verifier(deps, service_name, verifier)?)
            .map_err(|err| err.into()),
        QueryMsg::Service { service_name } => {
            to_json_binary(&query::service(deps, service_name)?).map_err(|err| err.into())
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    migrations::v0_4_1::migrate(deps.storage)?;

    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::default())
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use axelar_wasm_std::error::err_contains;
    use axelar_wasm_std::nonempty;
    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{coins, from_json, CosmosMsg, Empty, OwnedDeps, StdResult, Uint128};
    use router_api::ChainName;

    use super::*;
    use crate::state::{WeightedVerifier, VERIFIER_WEIGHT};

    const GOVERNANCE_ADDRESS: &str = "governance";
    const UNAUTHORIZED_ADDRESS: &str = "unauthorized";
    const COORDINATOR_ADDRESS: &str = "coordinator_address";
    const VERIFIER_ADDRESS: &str = "verifier";
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

    #[test]
    fn register_service() {
        let mut deps = setup();

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: "validators".into(),
                coordinator_contract: Addr::unchecked("nowhere"),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond: Uint128::one().try_into().unwrap(),
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
                coordinator_contract: Addr::unchecked("nowhere"),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond: Uint128::one().try_into().unwrap(),
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        )
        .unwrap_err();
        assert!(err_contains!(
            err.report,
            permission_control::Error,
            permission_control::Error::PermissionDenied { .. }
        ));
    }

    #[test]
    fn authorize_verifier() {
        let mut deps = setup();

        let service_name = "validators";
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked("nowhere"),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond: Uint128::one().try_into().unwrap(),
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
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![Addr::unchecked("verifier").into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(UNAUTHORIZED_ADDRESS, &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![Addr::unchecked("verifier").into()],
                service_name: service_name.into(),
            },
        )
        .unwrap_err();
        assert!(err_contains!(
            err.report,
            permission_control::Error,
            permission_control::Error::PermissionDenied { .. }
        ));
    }

    #[test]
    fn bond_verifier() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked("nowhere"),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond: min_verifier_bond.try_into().unwrap(),
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
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![VERIFIER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                VERIFIER_ADDRESS,
                &coins(min_verifier_bond.u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());
    }

    #[test]
    fn bond_verifier_zero_bond_should_fail() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked("nowhere"),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond: min_verifier_bond.try_into().unwrap(),
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
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![VERIFIER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(VERIFIER_ADDRESS, &[]),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_err());
    }

    #[test]
    fn register_chain_support() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked("nowhere"),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond: min_verifier_bond.try_into().unwrap(),
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
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![VERIFIER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                VERIFIER_ADDRESS,
                &coins(min_verifier_bond.u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = ChainName::from_str("ethereum").unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(VERIFIER_ADDRESS, &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            verifiers,
            vec![WeightedVerifier {
                verifier_info: Verifier {
                    address: Addr::unchecked(VERIFIER_ADDRESS),
                    bonding_state: BondingState::Bonded {
                        amount: min_verifier_bond.try_into().unwrap(),
                    },
                    authorization_state: AuthorizationState::Authorized,
                    service_name: service_name.into()
                },
                weight: VERIFIER_WEIGHT
            }]
        );

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name: ChainName::from_str("random chain").unwrap(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(verifiers, vec![]);
    }

    /// If a bonded and authorized verifier deregisters support for a chain they previously registered support for,
    /// that verifier should no longer be part of the active verifier set for that chain
    #[test]
    fn register_and_deregister_support_for_single_chain() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked("nowhere"),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond: min_verifier_bond.try_into().unwrap(),
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
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![VERIFIER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                VERIFIER_ADDRESS,
                &coins(min_verifier_bond.u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = ChainName::from_str("ethereum").unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(VERIFIER_ADDRESS, &[]),
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
            mock_info(VERIFIER_ADDRESS, &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(verifiers, vec![]);
    }

    /// Same setting and goal as register_and_deregister_support_for_single_chain() but for multiple chains.
    #[test]
    fn register_and_deregister_support_for_multiple_chains() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond: min_verifier_bond.try_into().unwrap(),
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
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![VERIFIER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                VERIFIER_ADDRESS,
                &coins(min_verifier_bond.u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
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
            mock_info(VERIFIER_ADDRESS, &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: chains.clone(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(VERIFIER_ADDRESS, &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: chains.clone(),
            },
        );
        assert!(res.is_ok());

        for chain in chains {
            let verifiers: Vec<WeightedVerifier> = from_json(
                query(
                    deps.as_ref(),
                    mock_env(),
                    QueryMsg::ActiveVerifiers {
                        service_name: service_name.into(),
                        chain_name: chain,
                    },
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(verifiers, vec![]);
        }
    }

    /// If a bonded and authorized verifier deregisters support for the first chain among multiple chains,
    /// they should remain part of the active verifier set for all chains except the first one.
    #[test]
    fn register_for_multiple_chains_deregister_for_first_one() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond: min_verifier_bond.try_into().unwrap(),
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
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![VERIFIER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                VERIFIER_ADDRESS,
                &coins(min_verifier_bond.u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
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
            mock_info(VERIFIER_ADDRESS, &[]),
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
            mock_info(VERIFIER_ADDRESS, &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chains[0].clone()],
            },
        );
        assert!(res.is_ok());

        // Verify that verifier is not associated with the deregistered chain
        let deregistered_chain = chains[0].clone();
        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name: deregistered_chain,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(verifiers, vec![]);

        // Verify that verifier is still associated with other chains
        for chain in chains.iter().skip(1) {
            let verifiers: Vec<WeightedVerifier> = from_json(
                query(
                    deps.as_ref(),
                    mock_env(),
                    QueryMsg::ActiveVerifiers {
                        service_name: service_name.into(),
                        chain_name: chain.clone(),
                    },
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(
                verifiers,
                vec![WeightedVerifier {
                    verifier_info: Verifier {
                        address: Addr::unchecked(VERIFIER_ADDRESS),
                        bonding_state: BondingState::Bonded {
                            amount: min_verifier_bond.try_into().unwrap(),
                        },
                        authorization_state: AuthorizationState::Authorized,
                        service_name: service_name.into()
                    },
                    weight: VERIFIER_WEIGHT
                }]
            );
        }
    }

    /// If a bonded and authorized verifier registers support for one chain and later deregisters support for another chain,
    /// the active verifier set for the original chain should remain unaffected by the deregistration.
    #[test]
    fn register_support_for_a_chain_deregister_support_for_another_chain() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
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
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![VERIFIER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                VERIFIER_ADDRESS,
                &coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = ChainName::from_str("ethereum").unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(VERIFIER_ADDRESS, &[]),
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
            mock_info(VERIFIER_ADDRESS, &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![second_chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            verifiers,
            vec![WeightedVerifier {
                verifier_info: Verifier {
                    address: Addr::unchecked(VERIFIER_ADDRESS),
                    bonding_state: BondingState::Bonded {
                        amount: min_verifier_bond
                    },
                    authorization_state: AuthorizationState::Authorized,
                    service_name: service_name.into()
                },
                weight: VERIFIER_WEIGHT
            }]
        );
    }

    /// If a bonded and authorized verifier registers, deregisters, and again registers their support for a single chain,
    /// the active verifier set of that chain should include the verifier.
    #[test]
    fn register_deregister_register_support_for_single_chain() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
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
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![VERIFIER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                VERIFIER_ADDRESS,
                &coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = ChainName::from_str("ethereum").unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(VERIFIER_ADDRESS, &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(VERIFIER_ADDRESS, &[]),
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
            mock_info(VERIFIER_ADDRESS, &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            verifiers,
            vec![WeightedVerifier {
                verifier_info: Verifier {
                    address: Addr::unchecked(VERIFIER_ADDRESS),
                    bonding_state: BondingState::Bonded {
                        amount: min_verifier_bond
                    },
                    authorization_state: AuthorizationState::Authorized,
                    service_name: service_name.into()
                },
                weight: VERIFIER_WEIGHT
            }]
        );
    }

    /// If a bonded and authorized verifier deregisters their support for a chain they have not previously registered
    /// support for, the call should be ignored and the active verifier set of the chain should be intact.
    #[test]
    fn deregister_previously_unsupported_single_chain() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
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
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![VERIFIER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                VERIFIER_ADDRESS,
                &coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = ChainName::from_str("ethereum").unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(VERIFIER_ADDRESS, &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(verifiers, vec![])
    }

    /// If an unbonded but authorized verifier deregisters support for a chain they previously registered support for,
    /// that verifier should not be part of the active verifier set for that chain.
    #[test]
    fn register_and_deregister_support_for_single_chain_unbonded() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
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
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![VERIFIER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = ChainName::from_str("ethereum").unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(VERIFIER_ADDRESS, &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(VERIFIER_ADDRESS, &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(verifiers, vec![]);
    }

    /// If a verifier that is not part of a service deregisters support for a chain from that specific service,
    /// process should return a contract error of type VerifierNotFound.
    #[test]
    fn deregister_from_unregistered_verifier_single_chain() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
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
            mock_info(VERIFIER_ADDRESS, &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        )
        .unwrap_err();

        assert!(err_contains!(
            err.report,
            permission_control::Error,
            permission_control::Error::WhitelistNotFound { .. }
        ));

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(verifiers, vec![]);
    }

    /// If a verifier deregisters support for a chain of an unregistered service,
    /// process should return a contract error of type ServiceNotFound.
    #[test]
    fn deregister_single_chain_for_nonexistent_service() {
        let mut deps = setup();

        let service_name = "validators";
        let chain_name = ChainName::from_str("ethereum").unwrap();
        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(VERIFIER_ADDRESS, &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        )
        .unwrap_err();

        assert!(err_contains!(
            err.report,
            permission_control::Error,
            permission_control::Error::WhitelistNotFound { .. }
        ));
    }

    #[test]
    fn unbond_verifier() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
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
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![VERIFIER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                VERIFIER_ADDRESS,
                &coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = ChainName::from_str("ethereum").unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(VERIFIER_ADDRESS, &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(VERIFIER_ADDRESS, &[]),
            ExecuteMsg::UnbondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(verifiers, vec![])
    }

    #[test]
    fn bond_wrong_denom() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                VERIFIER_ADDRESS,
                &coins(min_verifier_bond.into_inner().u128(), "funnydenom"),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        )
        .unwrap_err();

        assert!(err_contains!(
            err.report,
            ContractError,
            ContractError::WrongDenom
        ));
    }

    #[test]
    fn bond_but_not_authorized() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
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
                VERIFIER_ADDRESS,
                &coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = ChainName::from_str("ethereum").unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(VERIFIER_ADDRESS, &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(verifiers, vec![])
    }

    #[test]
    fn bond_but_not_enough() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
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
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![VERIFIER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                VERIFIER_ADDRESS,
                &coins(min_verifier_bond.into_inner().u128() / 2, AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = ChainName::from_str("ethereum").unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(VERIFIER_ADDRESS, &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(verifiers, vec![])
    }

    #[test]
    fn bond_before_authorize() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
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
                VERIFIER_ADDRESS,
                &coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![VERIFIER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = ChainName::from_str("ethereum").unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(VERIFIER_ADDRESS, &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            verifiers,
            vec![WeightedVerifier {
                verifier_info: Verifier {
                    address: Addr::unchecked(VERIFIER_ADDRESS),
                    bonding_state: BondingState::Bonded {
                        amount: min_verifier_bond
                    },
                    authorization_state: AuthorizationState::Authorized,
                    service_name: service_name.into()
                },
                weight: VERIFIER_WEIGHT
            }]
        );
    }

    #[test]
    fn unbond_then_rebond() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
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
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![VERIFIER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                VERIFIER_ADDRESS,
                &coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = ChainName::from_str("ethereum").unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(VERIFIER_ADDRESS, &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(VERIFIER_ADDRESS, &[]),
            ExecuteMsg::UnbondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(VERIFIER_ADDRESS, &[]),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            verifiers,
            vec![WeightedVerifier {
                verifier_info: Verifier {
                    address: Addr::unchecked(VERIFIER_ADDRESS),
                    bonding_state: BondingState::Bonded {
                        amount: min_verifier_bond
                    },
                    authorization_state: AuthorizationState::Authorized,
                    service_name: service_name.into()
                },
                weight: VERIFIER_WEIGHT
            }]
        );
    }

    #[test]
    fn unbonding_period() {
        let mut deps = setup();

        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let service_name = "validators";
        let unbonding_period_days = 1;

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
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
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![VERIFIER_ADDRESS.into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                VERIFIER_ADDRESS,
                &coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = ChainName::from_str("ethereum").unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(VERIFIER_ADDRESS, &[]),
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
            mock_info(VERIFIER_ADDRESS, &[]),
            ExecuteMsg::UnbondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), Response::new());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(VERIFIER_ADDRESS, &[]),
            ExecuteMsg::ClaimStake {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::InvalidBondingState(
                BondingState::Unbonding {
                    unbonded_at: unbond_request_env.block.time,
                    amount: min_verifier_bond,
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
            mock_info(VERIFIER_ADDRESS, &[]),
            ExecuteMsg::ClaimStake {
                service_name: service_name.into(),
            },
        )
        .unwrap();
        assert_eq!(res.messages.len(), 1);
        assert_eq!(
            res.messages[0].msg,
            CosmosMsg::Bank(BankMsg::Send {
                to_address: VERIFIER_ADDRESS.into(),
                amount: coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION)
            })
        )
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn active_verifiers_should_not_return_less_than_min() {
        let mut deps = setup();

        let verifiers = vec![Addr::unchecked("verifier1"), Addr::unchecked("verifier2")];
        let min_num_verifiers = verifiers.len() as u16;

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let _ = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_verifiers,
                max_num_verifiers: Some(100),
                min_verifier_bond,
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
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: verifiers.iter().map(|w| w.into()).collect(),
                service_name: service_name.into(),
            },
        )
        .unwrap();

        let chain_name = ChainName::from_str("ethereum").unwrap();

        for verifier in &verifiers {
            // should return err until all verifiers are registered
            let res = query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name: chain_name.clone(),
                },
            );
            assert!(res.is_err());

            let _ = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(
                    verifier.as_str(),
                    &coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION),
                ),
                ExecuteMsg::BondVerifier {
                    service_name: service_name.into(),
                },
            )
            .unwrap();

            let _ = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(verifier.as_str(), &[]),
                ExecuteMsg::RegisterChainSupport {
                    service_name: service_name.into(),
                    chains: vec![chain_name.clone()],
                },
            )
            .unwrap();
        }

        // all verifiers registered, should not return err now
        let res: StdResult<Vec<WeightedVerifier>> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
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
            mock_info(verifiers[0].as_str(), &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        )
        .unwrap();
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::ActiveVerifiers {
                service_name: service_name.into(),
                chain_name: chain_name.clone(),
            },
        );
        assert!(res.is_err());
    }

    #[test]
    fn jail_verifier() {
        let mut deps = setup();

        // register a service
        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let unbonding_period_days = 10;
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        // given a bonded verifier
        let verifier1 = Addr::unchecked("verifier-1");
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                verifier1.as_str(),
                &coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        // when verifier is jailed
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::JailVerifiers {
                verifiers: vec![verifier1.clone().into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        // verifier cannot unbond
        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(verifier1.as_str(), &[]),
            ExecuteMsg::UnbondVerifier {
                service_name: service_name.into(),
            },
        )
        .unwrap_err();
        assert!(err_contains!(
            err.report,
            ContractError,
            ContractError::VerifierJailed
        ));

        // given a verifier passed unbonding period
        let verifier2 = Addr::unchecked("verifier-2");

        // bond verifier
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                verifier2.as_str(),
                &coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let mut unbond_request_env = mock_env();
        unbond_request_env.block.time = unbond_request_env.block.time.plus_days(1);

        // unbond verifier
        let res = execute(
            deps.as_mut(),
            unbond_request_env.clone(),
            mock_info(verifier2.as_str(), &[]),
            ExecuteMsg::UnbondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());
        let verifier: Verifier = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::Verifier {
                    service_name: service_name.into(),
                    verifier: verifier2.to_string(),
                },
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            verifier.bonding_state,
            BondingState::Unbonding {
                amount: min_verifier_bond,
                unbonded_at: unbond_request_env.block.time,
            }
        );

        // when verifier is jailed
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::JailVerifiers {
                verifiers: vec![verifier2.clone().into()],
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

        // verifier cannot claim stake
        let err = execute(
            deps.as_mut(),
            after_unbond_period_env,
            mock_info(verifier2.as_str(), &[]),
            ExecuteMsg::ClaimStake {
                service_name: service_name.into(),
            },
        )
        .unwrap_err();
        assert!(err_contains!(
            err.report,
            ContractError,
            ContractError::VerifierJailed
        ));
    }
}
