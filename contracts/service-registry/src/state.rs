use axelar_wasm_std::nonempty;
use cosmwasm_std::{Addr, Storage, Timestamp, Uint128};
use cw_storage_plus::{Index, IndexList, IndexedMap, KeyDeserialize, Map, MultiIndex};
use router_api::ChainName;
use service_registry_api::error::ContractError;
use service_registry_api::{AuthorizationState, BondingState, Service, Verifier};

type ServiceName = String;
type VerifierAddress = Addr;

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

pub const SERVICES: Map<&ServiceName, Service> = Map::new("services");
pub const VERIFIERS: Map<(&ServiceName, &VerifierAddress), Verifier> = Map::new("verifiers");

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

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::vec;

    use axelar_wasm_std::nonempty;
    use cosmwasm_std::testing::{mock_dependencies, MockApi};
    use cosmwasm_std::{Timestamp, Uint128};
    use service_registry_api::{AuthorizationState, BondingState, Verifier};

    use super::*;

    #[test]
    fn register_single_verifier_chain_single_call_success() {
        let mut deps = mock_dependencies();
        let verifier = MockApi::default().addr_make("verifier");
        let service_name = "validators";
        let chain_name = ChainName::from_str("ethereum").unwrap();
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
        let verifier = MockApi::default().addr_make("verifier");
        let service_name = "validators";
        let chain_names = vec![
            ChainName::from_str("ethereum").unwrap(),
            ChainName::from_str("cosmos").unwrap(),
        ];

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
        let verifier = MockApi::default().addr_make("verifier");
        let service_name = "validators";

        let first_chain_name = ChainName::from_str("ethereum").unwrap();
        let first_chains_vector = vec![first_chain_name.clone()];
        assert!(register_chains_support(
            deps.as_mut().storage,
            service_name.into(),
            first_chains_vector,
            verifier.clone()
        )
        .is_ok());

        let second_chain_name = ChainName::from_str("cosmos").unwrap();
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
        let verifier = MockApi::default().addr_make("verifier");
        let service_name = "validators";
        let chain_name = ChainName::from_str("ethereum").unwrap();
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
        let verifier = MockApi::default().addr_make("verifier");
        let service_name = "validators";
        let chain_names = vec![
            ChainName::from_str("ethereum").unwrap(),
            ChainName::from_str("cosmos").unwrap(),
        ];
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
        let verifier = MockApi::default().addr_make("verifier");
        let service_name = "validators";
        let chain_name = ChainName::from_str("ethereum").unwrap();
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
            address: MockApi::default().addr_make("verifier"),
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
            address: MockApi::default().addr_make("verifier"),
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
            address: MockApi::default().addr_make("verifier"),
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
            address: MockApi::default().addr_make("verifier"),
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
            address: MockApi::default().addr_make("verifier"),
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
            address: MockApi::default().addr_make("verifier"),
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
            address: MockApi::default().addr_make("verifier"),
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
            address: MockApi::default().addr_make("verifier"),
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
            address: MockApi::default().addr_make("verifier"),
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
            address: MockApi::default().addr_make("verifier"),
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
            address: MockApi::default().addr_make("verifier"),
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
            address: MockApi::default().addr_make("verifier"),
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
            address: MockApi::default().addr_make("verifier"),
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
            address: MockApi::default().addr_make("verifier"),
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
            address: MockApi::default().addr_make("verifier"),
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
            address: MockApi::default().addr_make("verifier"),
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
            address: MockApi::default().addr_make("verifier"),
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
        let verifier = Verifier {
            address: MockApi::default().addr_make("verifier"),
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
}
