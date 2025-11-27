use axelar_wasm_std::nonempty;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Order, Storage, Timestamp, Uint128};
use cw_storage_plus::{Bound, Index, IndexList, IndexedMap, KeyDeserialize, Map, MultiIndex};
use error_stack::{bail, report, ResultExt as _};
use report::ResultExt;
use router_api::ChainName;
use service_registry_api::error::ContractError;
use service_registry_api::AuthorizationState::Authorized;
use service_registry_api::{AuthorizationState, BondingState, Service, Verifier};
type ServiceName = String;
type VerifierAddress = Addr;
use error_stack::ensure;

#[cw_serde]
pub struct UpdatedServiceParams {
    pub min_num_verifiers: Option<u16>,
    pub max_num_verifiers: Option<Option<u16>>,
    pub min_verifier_bond: Option<nonempty::Uint128>,
    pub unbonding_period_days: Option<u16>,
}

impl From<crate::msg::UpdatedServiceParams> for UpdatedServiceParams {
    fn from(params: crate::msg::UpdatedServiceParams) -> Self {
        UpdatedServiceParams {
            min_num_verifiers: params.min_num_verifiers,
            max_num_verifiers: params.max_num_verifiers,
            min_verifier_bond: params.min_verifier_bond,
            unbonding_period_days: params.unbonding_period_days,
        }
    }
}

#[cw_serde]
pub struct ServiceParamsOverride {
    pub min_num_verifiers: Option<u16>,
    pub max_num_verifiers: Option<Option<u16>>,
}

impl From<crate::msg::ServiceParamsOverride> for ServiceParamsOverride {
    fn from(params: crate::msg::ServiceParamsOverride) -> Self {
        ServiceParamsOverride {
            min_num_verifiers: params.min_num_verifiers,
            max_num_verifiers: params.max_num_verifiers,
        }
    }
}

impl From<ServiceParamsOverride> for crate::msg::ServiceParamsOverride {
    fn from(params: ServiceParamsOverride) -> Self {
        crate::msg::ServiceParamsOverride {
            min_num_verifiers: params.min_num_verifiers,
            max_num_verifiers: params.max_num_verifiers,
        }
    }
}

pub struct VerifierPerChainIndexes<'a> {
    pub verifier_address: MultiIndex<
        'a,
        (ServiceName, VerifierAddress),
        (),
        (ServiceName, ChainName, VerifierAddress),
    >,
}

impl IndexList<()> for VerifierPerChainIndexes<'_> {
    fn get_indexes(&'_ self) -> Box<dyn Iterator<Item = &'_ dyn Index<()>> + '_> {
        let v: Vec<&dyn Index<()>> = vec![&self.verifier_address];
        Box::new(v.into_iter())
    }
}

pub const VERIFIERS_PER_CHAIN: IndexedMap<
    (ServiceName, ChainName, VerifierAddress),
    (),
    VerifierPerChainIndexes,
> = IndexedMap::new(
    "verifiers_per_chain",
    VerifierPerChainIndexes {
        verifier_address: MultiIndex::new(
            |pk: &[u8], _: &()| {
                let (service_name, _, verifier) =
                    <(ServiceName, ChainName, VerifierAddress)>::from_slice(pk)
                        .expect("invalid primary key");
                (service_name, verifier)
            },
            "verifiers_per_chain",
            "verifiers_per_chain__address",
        ),
    },
);

/// For now, all verifiers have equal weight, regardless of amount bonded
pub const VERIFIER_WEIGHT: nonempty::Uint128 = nonempty::Uint128::one();
pub const VERIFIERS: Map<(&ServiceName, &VerifierAddress), Verifier> = Map::new("verifiers");

const SERVICES: Map<&ServiceName, Service> = Map::new("services");
const SERVICE_OVERRIDES: Map<(&ServiceName, &ChainName), ServiceParamsOverride> =
    Map::new("service_overrides");

const AUTHORIZED_VERIFIER_COUNT: Map<&ServiceName, u16> = Map::new("authorized_verifier_count");

pub fn service(
    storage: &dyn Storage,
    service_name: &ServiceName,
    chain: Option<&ChainName>,
) -> error_stack::Result<Service, ContractError> {
    let service = SERVICES
        .may_load(storage, service_name)
        .change_context(ContractError::StorageError)?
        .ok_or(report!(ContractError::ServiceNotFound))?;

    let params_override = chain
        .map(|chain| {
            SERVICE_OVERRIDES
                .may_load(storage, (service_name, chain))
                .change_context(ContractError::StorageError)
        })
        .transpose()?
        .flatten();

    match params_override {
        Some(params_override) => Ok(Service {
            min_num_verifiers: params_override
                .min_num_verifiers
                .unwrap_or(service.min_num_verifiers),
            max_num_verifiers: params_override
                .max_num_verifiers
                .unwrap_or(service.max_num_verifiers),
            ..service
        }),
        None => Ok(service),
    }
}

pub fn services(
    storage: &dyn Storage,
    service_name: Option<&ServiceName>,
    limit: nonempty::Usize,
) -> error_stack::Result<Vec<Service>, ContractError> {
    let start = service_name.map(Bound::exclusive);

    let services: Vec<_> = SERVICES
        .range(storage, start, None, Order::Ascending)
        .filter_map(|res| match res {
            Ok((_, res)) => Some(res),
            _ => None,
        })
        .take(limit.into())
        .collect();

    Ok(services)
}

pub fn save_new_service(
    storage: &mut dyn Storage,
    service_name: &ServiceName,
    service: Service,
) -> error_stack::Result<Service, ContractError> {
    AUTHORIZED_VERIFIER_COUNT
        .update(storage, service_name, |count| match count {
            None => Ok(0u16),
            Some(_) => Err(ContractError::ServiceAlreadyExists),
        })
        .change_context(ContractError::StorageError)?;

    SERVICES
        .update(storage, service_name, |s| match s {
            None => Ok(service),
            _ => Err(ContractError::ServiceAlreadyExists),
        })
        .into_report()
}

pub fn update_authorized_verifier_count(
    storage: &mut dyn Storage,
    service_name: &ServiceName,
) -> error_stack::Result<u16, ContractError> {
    let verifier_count: usize = VERIFIERS
        .prefix(service_name)
        .range(storage, None, None, Order::Ascending)
        .filter_map(|v| match v {
            Ok((_, ver)) => match ver.authorization_state {
                AuthorizationState::Authorized => Some(()),
                _ => None,
            },
            _ => None,
        })
        .collect::<Vec<()>>()
        .len();

    let total = u16::try_from(verifier_count).map_err(|_| ContractError::VerifierLimitExceeded)?;

    AUTHORIZED_VERIFIER_COUNT
        .update(storage, service_name, |_| Ok::<u16, ContractError>(total))
        .change_context(ContractError::StorageError)
}

pub fn has_service(storage: &dyn Storage, service_name: &ServiceName) -> bool {
    SERVICES.has(storage, service_name)
}

pub fn update_service(
    storage: &mut dyn Storage,
    service_name: &ServiceName,
    updated_service_params: UpdatedServiceParams,
) -> error_stack::Result<Service, ContractError> {
    if let Some(Some(max_verifiers_limit)) = updated_service_params.max_num_verifiers {
        let current_authorized = number_of_authorized_verifiers(storage, service_name)?;

        ensure!(
            max_verifiers_limit >= current_authorized,
            ContractError::MaxVerifiersSetBelowCurrent(max_verifiers_limit, current_authorized)
        );
    }

    SERVICES
        .update(storage, service_name, |service| match service {
            None => Err(ContractError::ServiceNotFound),
            Some(service) => Ok(Service {
                min_num_verifiers: updated_service_params
                    .min_num_verifiers
                    .unwrap_or(service.min_num_verifiers),
                max_num_verifiers: updated_service_params
                    .max_num_verifiers
                    .unwrap_or(service.max_num_verifiers),
                min_verifier_bond: updated_service_params
                    .min_verifier_bond
                    .unwrap_or(service.min_verifier_bond),
                unbonding_period_days: updated_service_params
                    .unbonding_period_days
                    .unwrap_or(service.unbonding_period_days),
                ..service
            }),
        })
        .into_report()
}

pub fn save_service_override(
    storage: &mut dyn Storage,
    service_name: &ServiceName,
    chain: &ChainName,
    service_params_override: &ServiceParamsOverride,
) -> error_stack::Result<(), ContractError> {
    if !has_service(storage, service_name) {
        bail!(ContractError::ServiceNotFound);
    }

    SERVICE_OVERRIDES
        .save(storage, (service_name, chain), service_params_override)
        .into_report()
}

pub fn remove_service_override(
    storage: &mut dyn Storage,
    service_name: &ServiceName,
    chain: &ChainName,
) -> error_stack::Result<(), ContractError> {
    if !SERVICE_OVERRIDES.has(storage, (service_name, chain)) {
        bail!(ContractError::ServiceOverrideNotFound);
    }

    SERVICE_OVERRIDES.remove(storage, (service_name, chain));

    Ok(())
}

pub fn may_load_service_params_override(
    storage: &dyn Storage,
    service_name: &ServiceName,
    chain: &ChainName,
) -> error_stack::Result<Option<ServiceParamsOverride>, ContractError> {
    SERVICE_OVERRIDES
        .may_load(storage, (service_name, chain))
        .change_context(ContractError::StorageError)
}

pub fn update_verifier_authorization_status(
    storage: &mut dyn Storage,
    service_name: ServiceName,
    auth_state: AuthorizationState,
    verifiers: Vec<Addr>,
) -> error_stack::Result<(), ContractError> {
    let mut authorized_count_change = 0i16;

    for verifier_addr in verifiers {
        VERIFIERS
            .update(
                storage,
                (&service_name, &verifier_addr.clone()),
                |existing_verifier| -> std::result::Result<Verifier, ContractError> {
                    let verifier_auth_state = auth_state.clone();
                    let previous_state = existing_verifier
                        .as_ref()
                        .map(|verifier| &verifier.authorization_state);

                    authorized_count_change = authorized_count_change
                        .checked_add(calculate_auth_verifier_count_change(
                            previous_state,
                            &verifier_auth_state,
                        ))
                        .ok_or(ContractError::AuthorizedVerifiersIntegerOverflow)?;

                    let new_verifier = match existing_verifier {
                        Some(mut verifier) => {
                            verifier.authorization_state = verifier_auth_state;
                            verifier
                        }

                        None => Verifier {
                            address: verifier_addr,
                            bonding_state: BondingState::Unbonded,
                            authorization_state: verifier_auth_state,
                            service_name: service_name.clone(),
                        },
                    };

                    Ok(new_verifier)
                },
            )
            .change_context(ContractError::StorageError)?;
    }
    apply_authorized_count_change(storage, &service_name, authorized_count_change)?;
    Ok(())
}

pub fn number_of_authorized_verifiers(
    storage: &dyn Storage,
    service_name: &ServiceName,
) -> error_stack::Result<u16, ContractError> {
    let count = AUTHORIZED_VERIFIER_COUNT
        .may_load(storage, service_name)
        .change_context(ContractError::StorageError)?
        .ok_or(report!(ContractError::ServiceNotFound))?;
    Ok(count)
}

pub fn bond_verifier(
    verifier: Verifier,
    to_add: Option<nonempty::Uint128>,
) -> Result<Verifier, ContractError> {
    let amount: nonempty::Uint128 = match verifier.bonding_state {
        BondingState::Bonded { amount }
        | BondingState::RequestedUnbonding { amount }
        | BondingState::Unbonding {
            amount,
            unbonded_at: _,
        } => amount
            .into_inner()
            .checked_add(to_add.map(Uint128::from).unwrap_or(Uint128::zero()))
            .map_err(ContractError::Overflow)?
            .try_into()?,
        BondingState::Unbonded => to_add.ok_or(ContractError::NoFundsToBond)?,
    };

    Ok(Verifier {
        bonding_state: BondingState::Bonded { amount },
        ..verifier
    })
}

pub fn unbond_verifier(
    verifier: Verifier,
    can_unbond: bool,
    time: Timestamp,
) -> Result<Verifier, ContractError> {
    if verifier.authorization_state == AuthorizationState::Jailed {
        return Err(ContractError::VerifierJailed);
    }

    let bonding_state = match verifier.bonding_state {
        BondingState::Bonded { amount } | BondingState::RequestedUnbonding { amount } => {
            if can_unbond {
                BondingState::Unbonding {
                    unbonded_at: time,
                    amount,
                }
            } else {
                BondingState::RequestedUnbonding { amount }
            }
        }
        _ => return Err(ContractError::InvalidBondingState(verifier.bonding_state)),
    };

    Ok(Verifier {
        bonding_state,
        ..verifier
    })
}

pub fn claim_verifier_stake(
    verifier: Verifier,
    time: Timestamp,
    unbonding_period_days: u64,
) -> Result<(Verifier, nonempty::Uint128), ContractError> {
    if verifier.authorization_state == AuthorizationState::Jailed {
        return Err(ContractError::VerifierJailed);
    }

    match verifier.bonding_state {
        BondingState::Unbonding {
            amount,
            unbonded_at,
        } if unbonded_at.plus_days(unbonding_period_days) <= time => Ok((
            Verifier {
                bonding_state: BondingState::Unbonded,
                ..verifier
            },
            amount,
        )),
        _ => Err(ContractError::InvalidBondingState(verifier.bonding_state)),
    }
}

pub fn register_chains_support(
    storage: &mut dyn Storage,
    service_name: String,
    chains: Vec<ChainName>,
    verifier: VerifierAddress,
) -> Result<(), ContractError> {
    for chain in chains.iter() {
        VERIFIERS_PER_CHAIN.save(
            storage,
            (service_name.clone(), chain.clone(), verifier.clone()),
            &(),
        )?;
    }
    Ok(())
}

pub fn deregister_chains_support(
    storage: &mut dyn Storage,
    service_name: String,
    chains: Vec<ChainName>,
    verifier: VerifierAddress,
) -> Result<(), ContractError> {
    for chain in chains {
        VERIFIERS_PER_CHAIN.remove(storage, (service_name.clone(), chain, verifier.clone()))?;
    }
    Ok(())
}

fn calculate_auth_verifier_count_change(
    previous_state: Option<&AuthorizationState>,
    auth_state: &AuthorizationState,
) -> i16 {
    match (previous_state, auth_state) {
        (Some(Authorized), Authorized) => 0,
        (Some(Authorized), _) => -1,
        (_, Authorized) => 1,
        _ => 0,
    }
}

fn apply_authorized_count_change(
    storage: &mut dyn Storage,
    service_name: &ServiceName,
    change: i16,
) -> error_stack::Result<(), ContractError> {
    if change == 0 {
        return Ok(());
    }

    AUTHORIZED_VERIFIER_COUNT
        .update(
            storage,
            service_name,
            |count| -> std::result::Result<u16, ContractError> {
                let current = count.ok_or(ContractError::ServiceNotFound)?;

                current
                    .checked_add_signed(change)
                    .ok_or(ContractError::AuthorizedVerifiersIntegerOverflow)
            },
        )
        .change_context(ContractError::StorageError)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::vec;

    use axelar_wasm_std::{assert_err_contains, nonempty};
    use cosmwasm_std::testing::{mock_dependencies, MockApi};
    use cosmwasm_std::{Timestamp, Uint128};
    use router_api::{chain_name, cosmos_addr};
    use service_registry_api::{AuthorizationState, BondingState, Verifier};

    use super::*;

    const VERIFIER: &str = "verifier";
    const SOLANA: &str = "solana";
    const ETHEREUM: &str = "ethereum";
    const COSMOS: &str = "cosmos";

    #[test]
    fn load_service_no_override() {
        let mut deps = mock_dependencies();
        let stored_service = save_mock_service(deps.as_mut().storage);
        let chain_name = chain_name!(SOLANA);

        let loaded_service = service(
            deps.as_ref().storage,
            &stored_service.name,
            Some(&chain_name),
        )
        .unwrap();

        assert_eq!(loaded_service, stored_service);
    }

    #[test]
    fn load_service_with_full_override() {
        let mut deps = mock_dependencies();
        let stored_service = save_mock_service(deps.as_mut().storage);
        let chain_name = chain_name!(SOLANA);
        let min_verifiers_override = 20;
        let max_verifiers_override = Some(20);

        let params_override = ServiceParamsOverride {
            min_num_verifiers: Some(min_verifiers_override),
            max_num_verifiers: Some(max_verifiers_override),
        };
        save_service_override(
            deps.as_mut().storage,
            &stored_service.name,
            &chain_name,
            &params_override,
        )
        .unwrap();

        let loaded_service = service(
            deps.as_ref().storage,
            &stored_service.name,
            Some(&chain_name),
        )
        .unwrap();

        let expected_service = Service {
            min_num_verifiers: min_verifiers_override,
            max_num_verifiers: max_verifiers_override,
            ..stored_service
        };

        assert_eq!(loaded_service, expected_service);
        assert_ne!(
            loaded_service.min_num_verifiers,
            stored_service.min_num_verifiers
        );
        assert_ne!(
            loaded_service.max_num_verifiers,
            stored_service.max_num_verifiers
        );
    }

    #[test]
    fn load_service_with_partial_override() {
        let mut deps = mock_dependencies();
        let stored_service = save_mock_service(deps.as_mut().storage);
        let chain_name = chain_name!(SOLANA);
        let max_verifiers_override = Some(20);

        let params_override = ServiceParamsOverride {
            min_num_verifiers: None,
            max_num_verifiers: Some(max_verifiers_override),
        };
        save_service_override(
            deps.as_mut().storage,
            &stored_service.name,
            &chain_name,
            &params_override,
        )
        .unwrap();

        let loaded_service = service(
            deps.as_ref().storage,
            &stored_service.name,
            Some(&chain_name),
        )
        .unwrap();

        let expected_service = Service {
            max_num_verifiers: max_verifiers_override,
            ..stored_service
        };

        assert_eq!(loaded_service, expected_service);
        assert_ne!(
            loaded_service.max_num_verifiers,
            stored_service.max_num_verifiers
        );
    }

    #[test]
    fn load_default_service_params() {
        let mut deps = mock_dependencies();
        let stored_service = save_mock_service(deps.as_mut().storage);
        let chain_name = chain_name!(SOLANA);
        let max_verifiers_override = Some(20);

        let params_override = ServiceParamsOverride {
            min_num_verifiers: None,
            max_num_verifiers: Some(max_verifiers_override),
        };
        save_service_override(
            deps.as_mut().storage,
            &stored_service.name,
            &chain_name,
            &params_override,
        )
        .unwrap();

        let loaded_service = service(deps.as_ref().storage, &stored_service.name, None).unwrap();

        assert_eq!(loaded_service, stored_service);
    }

    #[test]
    fn has_service_returns_true_if_service_exists() {
        let mut deps = mock_dependencies();
        let stored_service = save_mock_service(deps.as_mut().storage);

        assert!(has_service(deps.as_ref().storage, &stored_service.name));
    }

    #[test]
    fn has_service_returns_false_if_service_does_not_exist() {
        let deps = mock_dependencies();

        assert!(!has_service(
            deps.as_ref().storage,
            &"nonexistent".to_string()
        ));
    }

    #[test]
    fn remove_service_override_succeeds() {
        let mut deps = mock_dependencies();
        let stored_service = save_mock_service(deps.as_mut().storage);
        let chain_name = chain_name!(SOLANA);
        let max_verifiers_override = Some(20);

        let params_override = ServiceParamsOverride {
            min_num_verifiers: None,
            max_num_verifiers: Some(max_verifiers_override),
        };
        save_service_override(
            deps.as_mut().storage,
            &stored_service.name,
            &chain_name,
            &params_override,
        )
        .unwrap();

        let stored_override = SERVICE_OVERRIDES
            .load(deps.as_ref().storage, (&stored_service.name, &chain_name))
            .unwrap();
        assert_eq!(stored_override, params_override);

        let res = remove_service_override(deps.as_mut().storage, &stored_service.name, &chain_name);
        assert!(res.is_ok());

        assert!(SERVICE_OVERRIDES
            .may_load(deps.as_ref().storage, (&stored_service.name, &chain_name))
            .unwrap()
            .is_none());
    }

    #[test]
    fn remove_service_override_fails_if_service_override_does_not_exist() {
        let mut deps = mock_dependencies();
        let stored_service = save_mock_service(deps.as_mut().storage);
        let chain_name = chain_name!(SOLANA);

        let res = remove_service_override(deps.as_mut().storage, &stored_service.name, &chain_name);

        assert_err_contains!(res, ContractError, ContractError::ServiceOverrideNotFound);
    }

    #[test]
    fn may_load_service_params_override_succeeds() {
        let mut deps = mock_dependencies();
        let stored_service = save_mock_service(deps.as_mut().storage);
        let chain_name = chain_name!(SOLANA);
        let max_verifiers_override = Some(20);

        let params_override = ServiceParamsOverride {
            min_num_verifiers: None,
            max_num_verifiers: Some(max_verifiers_override),
        };
        save_service_override(
            deps.as_mut().storage,
            &stored_service.name,
            &chain_name,
            &params_override,
        )
        .unwrap();

        let loaded_override = may_load_service_params_override(
            deps.as_ref().storage,
            &stored_service.name,
            &chain_name,
        )
        .unwrap();

        assert_eq!(loaded_override, Some(params_override));
    }

    #[test]
    fn may_load_service_params_override_returns_none_if_service_override_does_not_exist() {
        let mut deps = mock_dependencies();
        let stored_service = save_mock_service(deps.as_mut().storage);
        let chain_name = chain_name!(SOLANA);

        let res = may_load_service_params_override(
            deps.as_mut().storage,
            &stored_service.name,
            &chain_name,
        );

        assert_eq!(res.unwrap(), None);
    }

    #[test]
    fn register_single_verifier_chain_single_call_success() {
        let mut deps = mock_dependencies();
        let verifier = cosmos_addr!(VERIFIER);
        let service_name = "validators";
        let chain_name = chain_name!(ETHEREUM);
        let chains = vec![chain_name.clone()];
        assert!(register_chains_support(
            deps.as_mut().storage,
            service_name.into(),
            chains,
            verifier.clone()
        )
        .is_ok());
    }

    #[test]
    fn register_multiple_verifier_chains_single_call_success() {
        let mut deps = mock_dependencies();
        let verifier = cosmos_addr!(VERIFIER);
        let service_name = "validators";
        let chain_names = vec![chain_name!(ETHEREUM), chain_name!(COSMOS)];

        assert!(register_chains_support(
            deps.as_mut().storage,
            service_name.into(),
            chain_names.clone(),
            verifier.clone()
        )
        .is_ok());
    }

    #[test]
    fn register_multiple_verifier_chains_multiple_calls_success() {
        let mut deps = mock_dependencies();
        let verifier = cosmos_addr!(VERIFIER);
        let service_name = "validators";

        let first_chain_name = chain_name!(ETHEREUM);
        let first_chains_vector = vec![first_chain_name.clone()];
        assert!(register_chains_support(
            deps.as_mut().storage,
            service_name.into(),
            first_chains_vector,
            verifier.clone()
        )
        .is_ok());

        let second_chain_name = chain_name!(COSMOS);
        let second_chains_vector = vec![second_chain_name.clone()];
        assert!(register_chains_support(
            deps.as_mut().storage,
            service_name.into(),
            second_chains_vector,
            verifier.clone()
        )
        .is_ok());
    }

    #[test]
    fn deregister_single_supported_chain_success() {
        let mut deps = mock_dependencies();
        let verifier = cosmos_addr!(VERIFIER);
        let service_name = "validators";
        let chain_name = chain_name!(ETHEREUM);
        let chains = vec![chain_name.clone()];
        assert!(register_chains_support(
            deps.as_mut().storage,
            service_name.into(),
            chains.clone(),
            verifier.clone()
        )
        .is_ok());

        assert!(deregister_chains_support(
            deps.as_mut().storage,
            service_name.into(),
            chains,
            verifier.clone()
        )
        .is_ok());
    }

    #[test]
    fn deregister_one_of_supported_chains_success() {
        let mut deps = mock_dependencies();
        let verifier = cosmos_addr!(VERIFIER);
        let service_name = "validators";
        let chain_names = vec![chain_name!(ETHEREUM), chain_name!(COSMOS)];
        assert!(register_chains_support(
            deps.as_mut().storage,
            service_name.into(),
            chain_names.clone(),
            verifier.clone()
        )
        .is_ok());

        assert!(deregister_chains_support(
            deps.as_mut().storage,
            service_name.into(),
            vec![chain_names[0].clone()],
            verifier.clone()
        )
        .is_ok());
    }

    #[test]
    fn deregister_unsupported_chain_success() {
        let mut deps = mock_dependencies();
        let verifier = cosmos_addr!(VERIFIER);
        let service_name = "validators";
        let chain_name = chain_name!(ETHEREUM);
        let chains = vec![chain_name.clone()];

        assert!(deregister_chains_support(
            deps.as_mut().storage,
            service_name.into(),
            chains,
            verifier.clone()
        )
        .is_ok());
    }

    #[test]
    fn test_bonded_add_bond() {
        let verifier = Verifier {
            address: cosmos_addr!(VERIFIER),
            bonding_state: BondingState::Bonded {
                amount: Uint128::from(100u32).try_into().unwrap(),
            },
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let res = bond_verifier(verifier, Some(Uint128::from(200u32).try_into().unwrap()));
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap().bonding_state,
            BondingState::Bonded {
                amount: Uint128::from(300u32).try_into().unwrap()
            }
        );
    }

    #[test]
    fn test_requested_unbonding_add_bond() {
        let verifier = Verifier {
            address: cosmos_addr!(VERIFIER),
            bonding_state: BondingState::RequestedUnbonding {
                amount: Uint128::from(100u32).try_into().unwrap(),
            },
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let res = bond_verifier(verifier, Some(Uint128::from(200u32).try_into().unwrap()));
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap().bonding_state,
            BondingState::Bonded {
                amount: Uint128::from(300u32).try_into().unwrap()
            }
        );
    }

    #[test]
    fn test_unbonding_add_bond() {
        let verifier = Verifier {
            address: cosmos_addr!(VERIFIER),
            bonding_state: BondingState::Unbonding {
                amount: Uint128::from(100u32).try_into().unwrap(),
                unbonded_at: Timestamp::from_nanos(0),
            },
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let res = bond_verifier(verifier, Some(Uint128::from(200u32).try_into().unwrap()));
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap().bonding_state,
            BondingState::Bonded {
                amount: Uint128::from(300u32).try_into().unwrap()
            }
        );
    }

    #[test]
    fn test_unbonded_add_bond() {
        let verifier = Verifier {
            address: cosmos_addr!(VERIFIER),
            bonding_state: BondingState::Unbonded,
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let res = bond_verifier(verifier, Some(Uint128::from(200u32).try_into().unwrap()));
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap().bonding_state,
            BondingState::Bonded {
                amount: Uint128::from(200u32).try_into().unwrap()
            }
        );
    }

    #[test]
    fn test_zero_bond() {
        let bonding_state = BondingState::Unbonded;

        let verifier = Verifier {
            address: cosmos_addr!(VERIFIER),
            bonding_state: bonding_state.clone(),
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let res = bond_verifier(verifier, None);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), ContractError::NoFundsToBond);
    }
    #[test]
    fn test_zero_bond_rebond() {
        let amount = nonempty::Uint128::try_from(100u128).unwrap();
        let bonding_state = BondingState::Unbonding {
            amount,
            unbonded_at: Timestamp::from_nanos(0),
        };

        let verifier = Verifier {
            address: cosmos_addr!(VERIFIER),
            bonding_state: bonding_state.clone(),
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let res = bond_verifier(verifier, None);
        assert!(res.is_ok());
        assert_eq!(res.unwrap().bonding_state, BondingState::Bonded { amount });
    }

    #[test]
    fn test_bonded_unbond() {
        let verifier = Verifier {
            address: cosmos_addr!(VERIFIER),
            bonding_state: BondingState::Bonded {
                amount: Uint128::from(100u32).try_into().unwrap(),
            },
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let unbonded_at = Timestamp::from_nanos(0);
        let res = unbond_verifier(verifier, true, unbonded_at);
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap().bonding_state,
            BondingState::Unbonding {
                amount: Uint128::from(100u32).try_into().unwrap(),
                unbonded_at
            }
        );
    }

    #[test]
    fn test_bonded_unbond_cant_unbond() {
        let verifier = Verifier {
            address: cosmos_addr!(VERIFIER),
            bonding_state: BondingState::Bonded {
                amount: Uint128::from(100u32).try_into().unwrap(),
            },
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let unbonded_at = Timestamp::from_nanos(0);
        let res = unbond_verifier(verifier, false, unbonded_at);
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap().bonding_state,
            BondingState::RequestedUnbonding {
                amount: Uint128::from(100u32).try_into().unwrap()
            }
        );
    }

    #[test]
    fn test_requested_unbonding_unbond() {
        let verifier = Verifier {
            address: cosmos_addr!(VERIFIER),
            bonding_state: BondingState::RequestedUnbonding {
                amount: Uint128::from(100u32).try_into().unwrap(),
            },
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let unbonded_at = Timestamp::from_nanos(0);
        let res = unbond_verifier(verifier, true, unbonded_at);
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap().bonding_state,
            BondingState::Unbonding {
                amount: Uint128::from(100u32).try_into().unwrap(),
                unbonded_at
            }
        );
    }

    #[test]
    fn test_requested_unbonding_cant_unbond() {
        let verifier = Verifier {
            address: cosmos_addr!(VERIFIER),
            bonding_state: BondingState::RequestedUnbonding {
                amount: Uint128::from(100u32).try_into().unwrap(),
            },
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let unbonded_at = Timestamp::from_nanos(0);
        let res = unbond_verifier(verifier, false, unbonded_at);
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap().bonding_state,
            BondingState::RequestedUnbonding {
                amount: Uint128::from(100u32).try_into().unwrap(),
            }
        );
    }

    #[test]
    fn test_unbonding_unbond() {
        let bonding_state = BondingState::Unbonding {
            amount: Uint128::from(100u32).try_into().unwrap(),
            unbonded_at: Timestamp::from_nanos(0),
        };

        let verifier = Verifier {
            address: cosmos_addr!(VERIFIER),
            bonding_state: bonding_state.clone(),
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let res = unbond_verifier(verifier.clone(), true, Timestamp::from_nanos(2));
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(bonding_state.clone())
        );

        let res = unbond_verifier(verifier, false, Timestamp::from_nanos(2));
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(bonding_state.clone())
        );
    }

    #[test]
    fn test_unbonded_unbond() {
        let bonding_state = BondingState::Unbonded;

        let verifier = Verifier {
            address: cosmos_addr!(VERIFIER),
            bonding_state: bonding_state.clone(),
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let res = unbond_verifier(verifier.clone(), true, Timestamp::from_nanos(2));
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(bonding_state.clone())
        );

        let res = unbond_verifier(verifier, false, Timestamp::from_nanos(2));
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(bonding_state.clone())
        );
    }

    #[test]
    fn test_bonded_claim_stake() {
        let bonding_state = BondingState::Bonded {
            amount: Uint128::from(100u32).try_into().unwrap(),
        };
        let verifier = Verifier {
            address: cosmos_addr!(VERIFIER),
            bonding_state: bonding_state.clone(),
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let res = claim_verifier_stake(verifier.clone(), Timestamp::from_seconds(60), 1);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(bonding_state.clone())
        );

        let res = claim_verifier_stake(verifier, Timestamp::from_seconds(60 * 60 * 24), 1);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(bonding_state.clone())
        );
    }

    #[test]
    fn test_requested_unbonding_claim_stake() {
        let bonding_state = BondingState::RequestedUnbonding {
            amount: Uint128::from(100u32).try_into().unwrap(),
        };
        let verifier = Verifier {
            address: cosmos_addr!(VERIFIER),
            bonding_state: bonding_state.clone(),
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let res = claim_verifier_stake(verifier.clone(), Timestamp::from_seconds(60), 1);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(bonding_state.clone())
        );

        let res = claim_verifier_stake(verifier, Timestamp::from_seconds(60 * 60 * 24), 1);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(bonding_state.clone())
        );
    }

    #[test]
    fn test_unbonding_claim_stake() {
        let bonding_state = BondingState::Unbonding {
            amount: Uint128::from(100u32).try_into().unwrap(),
            unbonded_at: Timestamp::from_nanos(0),
        };
        let verifier = Verifier {
            address: cosmos_addr!(VERIFIER),
            bonding_state: bonding_state.clone(),
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let res = claim_verifier_stake(verifier.clone(), Timestamp::from_seconds(60), 1);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(bonding_state.clone())
        );

        let res = claim_verifier_stake(verifier, Timestamp::from_seconds(60 * 60 * 24), 1);
        assert!(res.is_ok());

        let (verifier, amount) = res.unwrap();
        assert_eq!(
            (verifier.bonding_state, amount),
            (
                BondingState::Unbonded,
                Uint128::from(100u32).try_into().unwrap()
            )
        );
    }

    #[test]
    fn test_unbonded_claim_stake() {
        let bonding_state = BondingState::Unbonded;
        let verifier = Verifier {
            address: cosmos_addr!(VERIFIER),
            bonding_state: bonding_state.clone(),
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let res = claim_verifier_stake(verifier.clone(), Timestamp::from_seconds(60), 1);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(bonding_state.clone())
        );

        let res = claim_verifier_stake(verifier, Timestamp::from_seconds(60 * 60 * 24), 1);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(bonding_state.clone())
        );
    }

    #[test]
    fn jailed_verifier_cannot_unbond() {
        let verifier = Verifier {
            address: cosmos_addr!(VERIFIER),
            bonding_state: BondingState::Bonded {
                amount: Uint128::from(100u32).try_into().unwrap(),
            },
            authorization_state: AuthorizationState::Jailed,
            service_name: "validators".to_string(),
        };

        let res = unbond_verifier(verifier, true, Timestamp::from_nanos(0));
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), ContractError::VerifierJailed);
    }

    #[test]
    fn jailed_verifier_cannot_claim_stake() {
        let verifier: Verifier = Verifier {
            address: cosmos_addr!(VERIFIER),
            bonding_state: BondingState::Unbonding {
                amount: Uint128::from(100u32).try_into().unwrap(),
                unbonded_at: Timestamp::from_nanos(0),
            },
            authorization_state: AuthorizationState::Jailed,
            service_name: "validators".to_string(),
        };

        let res = claim_verifier_stake(verifier, Timestamp::from_nanos(1), 0);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), ContractError::VerifierJailed);
    }

    fn mock_service() -> Service {
        Service {
            name: "amplifier".to_string(),
            coordinator_contract: cosmos_addr!("coordinator"),
            min_num_verifiers: 1,
            max_num_verifiers: Some(10),
            min_verifier_bond: Uint128::from(100u32).try_into().unwrap(),
            bond_denom: "uaxl".to_string(),
            unbonding_period_days: 1,
            description: "description".to_string(),
        }
    }

    fn save_mock_service(storage: &mut dyn Storage) -> Service {
        let service = mock_service();
        save_new_service(storage, &service.name.clone(), service).unwrap()
    }

    #[test]
    fn test_update_verifier_authroization_status_succeed() {
        let mut deps = mock_dependencies();
        let service = save_mock_service(deps.as_mut().storage);
        let count = number_of_authorized_verifiers(deps.as_ref().storage, &service.name).unwrap();
        assert_eq!(count, 0);

        let verifier = cosmos_addr!(VERIFIER);
        update_verifier_authorization_status(
            deps.as_mut().storage,
            service.name.clone(),
            AuthorizationState::Authorized,
            vec![verifier.clone()],
        )
        .unwrap();

        let count = number_of_authorized_verifiers(deps.as_ref().storage, &service.name).unwrap();
        assert_eq!(count, 1);

        update_verifier_authorization_status(
            deps.as_mut().storage,
            service.name.clone(),
            AuthorizationState::NotAuthorized,
            vec![verifier],
        )
        .unwrap();

        let count = number_of_authorized_verifiers(deps.as_ref().storage, &service.name).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_update_service_max_verifiers_below_current_should_fail() {
        let mut deps = mock_dependencies();
        let service = save_mock_service(deps.as_mut().storage);

        let verifiers: Vec<Addr> = (0..5)
            .map(|i| MockApi::default().addr_make(&format!("verifier{}", i)))
            .collect();

        update_verifier_authorization_status(
            deps.as_mut().storage,
            service.name.clone(),
            AuthorizationState::Authorized,
            verifiers,
        )
        .unwrap();

        let params = UpdatedServiceParams {
            max_num_verifiers: Some(Some(4)),
            min_num_verifiers: None,
            min_verifier_bond: None,
            unbonding_period_days: None,
        };

        let result = update_service(deps.as_mut().storage, &service.name, params);
        assert!(result.is_err());
    }

    #[test]
    fn test_number_of_authorized_verifiers_return_err_when_service_not_found() {
        let deps = mock_dependencies();
        let nonexistent_service = "nonexistent_service".to_string();
        let result = number_of_authorized_verifiers(deps.as_ref().storage, &nonexistent_service);
        assert!(result.is_err());
        assert_err_contains!(result, ContractError, ContractError::ServiceNotFound);
    }

    #[test]
    fn test_calculate_auth_verifier_count_change_succeed() {
        let test_cases = vec![
            // (previous_state, new_state, expected_change, description)
            (
                None,
                AuthorizationState::Authorized,
                1,
                "New verifier becomes authorized",
            ),
            (
                Some(AuthorizationState::NotAuthorized),
                AuthorizationState::Authorized,
                1,
                "NotAuthorized -> Authorized",
            ),
            (
                Some(AuthorizationState::Authorized),
                AuthorizationState::NotAuthorized,
                -1,
                "Authorized -> NotAuthorized",
            ),
            (
                Some(AuthorizationState::Authorized),
                AuthorizationState::Authorized,
                0,
                "No change",
            ),
        ];

        for (previous_state, new_state, expected_change, description) in test_cases {
            let change = calculate_auth_verifier_count_change(previous_state.as_ref(), &new_state);

            assert_eq!(change, expected_change, "Test failed for: {}", description,);
        }
    }

    #[test]
    fn test_apply_authorized_count_change_should_suceed() {
        let mut deps = mock_dependencies();
        let service = save_mock_service(deps.as_mut().storage);

        AUTHORIZED_VERIFIER_COUNT
            .save(deps.as_mut().storage, &service.name, &5u16)
            .unwrap();

        let result = apply_authorized_count_change(deps.as_mut().storage, &service.name, 3);
        assert!(result.is_ok());

        let count = number_of_authorized_verifiers(deps.as_ref().storage, &service.name).unwrap();
        assert_eq!(count, 8);

        let result = apply_authorized_count_change(deps.as_mut().storage, &service.name, -2);
        assert!(result.is_ok());

        let count = number_of_authorized_verifiers(deps.as_ref().storage, &service.name).unwrap();
        assert_eq!(count, 6);

        let result = apply_authorized_count_change(deps.as_mut().storage, &service.name, 0);
        assert!(result.is_ok());

        let count = number_of_authorized_verifiers(deps.as_ref().storage, &service.name).unwrap();
        assert_eq!(count, 6);
    }

    #[test]
    fn test_apply_authorized_count_change_should_fail_when_overflow() {
        let mut deps = mock_dependencies();
        let service = save_mock_service(deps.as_mut().storage);

        AUTHORIZED_VERIFIER_COUNT
            .save(deps.as_mut().storage, &service.name, &u16::MAX)
            .unwrap();

        let result = apply_authorized_count_change(deps.as_mut().storage, &service.name, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_services_returns_empty_list_when_no_services() {
        let deps = mock_dependencies();
        let limit = nonempty::Usize::try_from(10).unwrap();

        let result = services(deps.as_ref().storage, None, limit);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_services_returns_single_service() {
        let mut deps = mock_dependencies();
        let service = save_mock_service(deps.as_mut().storage);
        let limit = nonempty::Usize::try_from(10).unwrap();

        let result = services(deps.as_ref().storage, None, limit);
        assert!(result.is_ok());

        let service_list = result.unwrap();
        assert_eq!(service_list.len(), 1);
        assert_eq!(service_list[0], service);
    }

    #[test]
    fn test_services_returns_multiple_services() {
        let mut deps = mock_dependencies();
        let limit = nonempty::Usize::try_from(10).unwrap();

        // Create multiple services
        let service1 = Service {
            name: "service1".to_string(),
            coordinator_contract: cosmos_addr!("coordinator"),
            min_num_verifiers: 1,
            max_num_verifiers: Some(10),
            min_verifier_bond: Uint128::from(100u32).try_into().unwrap(),
            bond_denom: "uaxl".to_string(),
            unbonding_period_days: 1,
            description: "description1".to_string(),
        };

        let service2 = Service {
            name: "service2".to_string(),
            coordinator_contract: cosmos_addr!("coordinator"),
            min_num_verifiers: 2,
            max_num_verifiers: Some(20),
            min_verifier_bond: Uint128::from(200u32).try_into().unwrap(),
            bond_denom: "uaxl".to_string(),
            unbonding_period_days: 2,
            description: "description2".to_string(),
        };

        save_new_service(deps.as_mut().storage, &service1.name, service1.clone()).unwrap();
        save_new_service(deps.as_mut().storage, &service2.name, service2.clone()).unwrap();

        let result = services(deps.as_ref().storage, None, limit);
        assert!(result.is_ok());

        let service_list = result.unwrap();
        assert_eq!(service_list.len(), 2);
        assert_eq!(service_list[0], service1);
        assert_eq!(service_list[1], service2);
    }

    #[test]
    fn test_services_respects_limit() {
        let mut deps = mock_dependencies();
        let limit = nonempty::Usize::try_from(2).unwrap();

        // Create 3 services
        for i in 1..=3 {
            let service = Service {
                name: format!("service{}", i),
                coordinator_contract: cosmos_addr!("coordinator"),
                min_num_verifiers: 1,
                max_num_verifiers: Some(10),
                min_verifier_bond: Uint128::from(100u32).try_into().unwrap(),
                bond_denom: "uaxl".to_string(),
                unbonding_period_days: 1,
                description: format!("description{}", i),
            };
            let service_name = service.name.clone();
            save_new_service(deps.as_mut().storage, &service_name, service).unwrap();
        }

        let result = services(deps.as_ref().storage, None, limit);
        assert!(result.is_ok());

        let service_list = result.unwrap();
        assert_eq!(service_list.len(), 2);
    }

    #[test]
    fn test_services_pagination_with_start() {
        let mut deps = mock_dependencies();
        let limit = nonempty::Usize::try_from(10).unwrap();

        // Create 3 services
        for i in 1..=3 {
            let service = Service {
                name: format!("service{}", i),
                coordinator_contract: cosmos_addr!("coordinator"),
                min_num_verifiers: 1,
                max_num_verifiers: Some(10),
                min_verifier_bond: Uint128::from(100u32).try_into().unwrap(),
                bond_denom: "uaxl".to_string(),
                unbonding_period_days: 1,
                description: format!("description{}", i),
            };
            let service_name = service.name.clone();
            save_new_service(deps.as_mut().storage, &service_name, service).unwrap();
        }

        let start_name = "service1".to_string();
        let result = services(deps.as_ref().storage, Some(&start_name), limit);
        assert!(result.is_ok());

        let service_list = result.unwrap();
        // Should return service2 and service3 (excluding service1)
        assert_eq!(service_list.len(), 2);
        assert_eq!(service_list[0].name, "service2");
        assert_eq!(service_list[1].name, "service3");
    }

    #[test]
    fn test_update_authorized_verifier_count_with_no_verifiers() {
        let mut deps = mock_dependencies();
        let service = save_mock_service(deps.as_mut().storage);

        let result = update_authorized_verifier_count(deps.as_mut().storage, &service.name);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);

        let count = number_of_authorized_verifiers(deps.as_ref().storage, &service.name).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_update_authorized_verifier_count_with_authorized_verifiers() {
        let mut deps = mock_dependencies();
        let service = save_mock_service(deps.as_mut().storage);

        // Create and authorize verifiers
        let verifiers: Vec<Addr> = (0..5)
            .map(|i| MockApi::default().addr_make(&format!("verifier{}", i)))
            .collect();

        for verifier in &verifiers {
            let v = Verifier {
                address: verifier.clone(),
                bonding_state: BondingState::Unbonded,
                authorization_state: AuthorizationState::Authorized,
                service_name: service.name.clone(),
            };
            VERIFIERS
                .save(deps.as_mut().storage, (&service.name, verifier), &v)
                .unwrap();
        }

        let result = update_authorized_verifier_count(deps.as_mut().storage, &service.name);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 5);

        let count = number_of_authorized_verifiers(deps.as_ref().storage, &service.name).unwrap();
        assert_eq!(count, 5);
    }

    #[test]
    fn test_update_authorized_verifier_count_excludes_not_authorized() {
        let mut deps = mock_dependencies();
        let service = save_mock_service(deps.as_mut().storage);

        // Create 3 authorized and 2 not authorized verifiers
        for i in 0..3 {
            let verifier = MockApi::default().addr_make(&format!("authorized{}", i));
            let v = Verifier {
                address: verifier.clone(),
                bonding_state: BondingState::Unbonded,
                authorization_state: AuthorizationState::Authorized,
                service_name: service.name.clone(),
            };
            VERIFIERS
                .save(deps.as_mut().storage, (&service.name, &verifier), &v)
                .unwrap();
        }

        for i in 0..2 {
            let verifier = MockApi::default().addr_make(&format!("notauthorized{}", i));
            let v = Verifier {
                address: verifier.clone(),
                bonding_state: BondingState::Unbonded,
                authorization_state: AuthorizationState::NotAuthorized,
                service_name: service.name.clone(),
            };
            VERIFIERS
                .save(deps.as_mut().storage, (&service.name, &verifier), &v)
                .unwrap();
        }

        let result = update_authorized_verifier_count(deps.as_mut().storage, &service.name);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 3);

        let count = number_of_authorized_verifiers(deps.as_ref().storage, &service.name).unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn test_update_authorized_verifier_count_excludes_jailed() {
        let mut deps = mock_dependencies();
        let service = save_mock_service(deps.as_mut().storage);

        // Create 2 authorized and 1 jailed verifier
        for i in 0..2 {
            let verifier = MockApi::default().addr_make(&format!("authorized{}", i));
            let v = Verifier {
                address: verifier.clone(),
                bonding_state: BondingState::Unbonded,
                authorization_state: AuthorizationState::Authorized,
                service_name: service.name.clone(),
            };
            VERIFIERS
                .save(deps.as_mut().storage, (&service.name, &verifier), &v)
                .unwrap();
        }

        let jailed_verifier = MockApi::default().addr_make("jailed");
        let v = Verifier {
            address: jailed_verifier.clone(),
            bonding_state: BondingState::Unbonded,
            authorization_state: AuthorizationState::Jailed,
            service_name: service.name.clone(),
        };
        VERIFIERS
            .save(deps.as_mut().storage, (&service.name, &jailed_verifier), &v)
            .unwrap();

        let result = update_authorized_verifier_count(deps.as_mut().storage, &service.name);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 2);

        let count = number_of_authorized_verifiers(deps.as_ref().storage, &service.name).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_update_authorized_verifier_count_corrects_stale_count() {
        let mut deps = mock_dependencies();
        let service = save_mock_service(deps.as_mut().storage);

        // Manually set a stale count
        AUTHORIZED_VERIFIER_COUNT
            .save(deps.as_mut().storage, &service.name, &100u16)
            .unwrap();

        // Add only 3 actual authorized verifiers
        for i in 0..3 {
            let verifier = MockApi::default().addr_make(&format!("verifier{}", i));
            let v = Verifier {
                address: verifier.clone(),
                bonding_state: BondingState::Unbonded,
                authorization_state: AuthorizationState::Authorized,
                service_name: service.name.clone(),
            };
            VERIFIERS
                .save(deps.as_mut().storage, (&service.name, &verifier), &v)
                .unwrap();
        }

        // Update should correct the count
        let result = update_authorized_verifier_count(deps.as_mut().storage, &service.name);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 3);

        let count = number_of_authorized_verifiers(deps.as_ref().storage, &service.name).unwrap();
        assert_eq!(count, 3);
    }
}
