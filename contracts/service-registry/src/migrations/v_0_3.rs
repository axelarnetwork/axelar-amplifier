//! Migrate includes:
//! - rename min_num_workers, max_num_workers and min_worker_bond fields in 'Service` struct
//! - rename WORKERS_PER_CHAIN to VERIFIERS_PER_CHAIN
//! - rename CHAINS_PER_WORKER to CHAINS_PER_VERIFIER
//! - rename WORKERS to VERIFIERS

use cosmwasm_std::{DepsMut, Order, Response, Storage};

use crate::error::ContractError;
use crate::state::{
    Service, Verifier, CHAINS_PER_VERIFIER, SERVICES, VERIFIERS, VERIFIERS_PER_CHAIN,
};

mod v0_2_state {
    use std::collections::HashSet;

    use cosmwasm_schema::cw_serde;
    use cosmwasm_std::{Addr, Uint128};
    use cw_storage_plus::Map;
    use router_api::ChainName;

    use crate::state::{AuthorizationState, BondingState};

    #[cw_serde]
    pub struct Service {
        pub name: String,
        pub service_contract: Addr,
        pub min_num_workers: u16,
        pub max_num_workers: Option<u16>,
        pub min_worker_bond: Uint128,
        pub bond_denom: String,
        pub unbonding_period_days: u16,
        pub description: String,
    }

    #[cw_serde]
    pub struct Worker {
        pub address: Addr,
        pub bonding_state: BondingState,
        pub authorization_state: AuthorizationState,
        pub service_name: String,
    }

    type ChainNames = HashSet<ChainName>;
    type ServiceName = str;
    type WorkerAddress = Addr;

    pub const SERVICES: Map<&ServiceName, Service> = Map::new("services");
    pub const WORKERS_PER_CHAIN: Map<(&ServiceName, &ChainName, &WorkerAddress), ()> =
        Map::new("workers_per_chain");
    pub const CHAINS_PER_WORKER: Map<(&ServiceName, &WorkerAddress), ChainNames> =
        Map::new("chains_per_worker");
    pub const WORKERS: Map<(&ServiceName, &WorkerAddress), Worker> = Map::new("workers");
}

pub fn migrate(deps: DepsMut) -> Result<Response, ContractError> {
    migrate_services(deps.storage)?;
    migrate_workers_per_chain(deps.storage)?;
    migrate_chains_per_worker(deps.storage)?;
    migrate_workers(deps.storage)?;

    Ok(Response::new())
}

fn migrate_services(store: &mut dyn Storage) -> Result<(), ContractError> {
    let keys_and_services = v0_2_state::SERVICES
        .range(store, None, None, Order::Ascending)
        .map(|result| {
            result.map(|(service_name, service)| {
                (
                    service_name,
                    Service {
                        name: service.name,
                        service_contract: service.service_contract,
                        min_num_verifiers: service.min_num_workers,
                        max_num_verifiers: service.max_num_workers,
                        min_verifier_bond: service.min_worker_bond,
                        bond_denom: service.bond_denom,
                        unbonding_period_days: service.unbonding_period_days,
                        description: service.description,
                    },
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    for (service_name, new_service) in keys_and_services {
        SERVICES.save(store, &service_name, &new_service)?;
    }

    Ok(())
}

fn migrate_workers_per_chain(store: &mut dyn Storage) -> Result<(), ContractError> {
    let keys_and_value_pairs = v0_2_state::WORKERS_PER_CHAIN
        .range(store, None, None, Order::Ascending)
        .collect::<Result<Vec<_>, _>>()?;

    for ((service_name, chain_name, verifier_address), _) in keys_and_value_pairs {
        let key = (service_name.as_str(), &chain_name, &verifier_address);
        VERIFIERS_PER_CHAIN.save(store, key, &())?;
        v0_2_state::WORKERS_PER_CHAIN.remove(store, key);
    }

    Ok(())
}

fn migrate_chains_per_worker(store: &mut dyn Storage) -> Result<(), ContractError> {
    let keys_and_value_pairs = v0_2_state::CHAINS_PER_WORKER
        .range(store, None, None, Order::Ascending)
        .collect::<Result<Vec<_>, _>>()?;

    for ((service_name, verifier_address), chain_name) in keys_and_value_pairs {
        let key = (service_name.as_str(), &verifier_address);
        CHAINS_PER_VERIFIER.save(store, key, &chain_name)?;
        v0_2_state::CHAINS_PER_WORKER.remove(store, key);
    }

    Ok(())
}

fn migrate_workers(store: &mut dyn Storage) -> Result<(), ContractError> {
    let keys_and_workers = v0_2_state::WORKERS
        .range(store, None, None, Order::Ascending)
        .collect::<Result<Vec<_>, _>>()?;

    for ((service_name, verifier_address), worker) in keys_and_workers {
        let key = (service_name.as_str(), &verifier_address);
        let verifier = Verifier {
            address: worker.address,
            bonding_state: worker.bonding_state,
            authorization_state: worker.authorization_state,
            service_name: worker.service_name,
        };
        VERIFIERS.save(store, key, &verifier)?;
        v0_2_state::WORKERS.remove(store, key);
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use cosmwasm_std::{testing::mock_dependencies, Addr, Storage, Uint128};

    use router_api::ChainName;

    use crate::{
        error::ContractError,
        migrations::v_0_3::{migrate, v0_2_state},
        state::{
            AuthorizationState, BondingState, Service, CHAINS_PER_VERIFIER, SERVICES, VERIFIERS,
            VERIFIERS_PER_CHAIN,
        },
    };

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn migration() {
        let mut deps = mock_dependencies();

        let service = v0_2_state::Service {
            name: "service".to_string(),
            service_contract: Addr::unchecked("service_contract"),
            min_num_workers: 1,
            max_num_workers: Some(2),
            min_worker_bond: 100u128.into(),
            bond_denom: "uaxl".to_string(),
            unbonding_period_days: 10,
            description: "description".to_string(),
        };

        let verifiers = vec![
            Addr::unchecked("verifier1"),
            Addr::unchecked("verifier2"),
            Addr::unchecked("verifier3"),
            Addr::unchecked("verifier4"),
        ];

        let chains: Vec<ChainName> = vec![
            "chain1".parse().unwrap(),
            "chain2".parse().unwrap(),
            "chain3".parse().unwrap(),
            "chain4".parse().unwrap(),
        ];

        set_up_v0_2_state(
            &mut deps.storage,
            service.clone(),
            verifiers.clone(),
            chains.clone(),
        );

        migrate(deps.as_mut()).unwrap();

        // verify new state
        assert_eq!(
            SERVICES.load(&deps.storage, &service.name).unwrap(),
            Service {
                name: service.name,
                service_contract: service.service_contract,
                min_num_verifiers: service.min_num_workers,
                max_num_verifiers: service.max_num_workers,
                min_verifier_bond: service.min_worker_bond,
                bond_denom: service.bond_denom,
                unbonding_period_days: service.unbonding_period_days,
                description: service.description,
            }
        );

        assert_eq!(
            VERIFIERS_PER_CHAIN
                .range(&deps.storage, None, None, cosmwasm_std::Order::Ascending)
                .count(),
            chains.len() * verifiers.len()
        );

        assert_eq!(
            CHAINS_PER_VERIFIER
                .range(&deps.storage, None, None, cosmwasm_std::Order::Ascending)
                .count(),
            chains.len()
        );
        assert_eq!(
            VERIFIERS
                .range(&deps.storage, None, None, cosmwasm_std::Order::Ascending)
                .count(),
            verifiers.len()
        );
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn set_up_v0_2_state(
        store: &mut dyn Storage,
        service: v0_2_state::Service,
        verifiers: Vec<Addr>,
        chains: Vec<ChainName>,
    ) {
        v0_2_state::SERVICES
            .save(store, &service.name, &service)
            .unwrap();

        for verifier in verifiers.iter() {
            for chain in chains.iter() {
                v0_2_state::WORKERS_PER_CHAIN
                    .save(store, (&service.name, chain, &verifier), &())
                    .unwrap();
            }

            v0_2_state::CHAINS_PER_WORKER
                .update(store, (&service.name, &verifier), |current_chains| {
                    let mut current_chains = current_chains.unwrap_or_default();
                    current_chains.extend(chains.iter().cloned());
                    Ok::<HashSet<ChainName>, ContractError>(current_chains)
                })
                .unwrap();

            let worker = v0_2_state::Worker {
                address: verifier.clone(),
                bonding_state: BondingState::Bonded {
                    amount: Uint128::from(1000000u128),
                },
                authorization_state: AuthorizationState::Authorized,
                service_name: service.name.clone(),
            };
            v0_2_state::WORKERS
                .save(store, (&service.name, verifier), &worker)
                .unwrap();
        }

        // verify state set up correctly
        assert_eq!(
            v0_2_state::SERVICES.load(store, &service.name).unwrap(),
            service
        );
        assert_eq!(
            v0_2_state::WORKERS_PER_CHAIN
                .range(store, None, None, cosmwasm_std::Order::Ascending)
                .count(),
            chains.len() * verifiers.len()
        );
        assert_eq!(
            v0_2_state::CHAINS_PER_WORKER
                .range(store, None, None, cosmwasm_std::Order::Ascending)
                .count(),
            chains.len()
        );
        assert_eq!(
            v0_2_state::WORKERS
                .range(store, None, None, cosmwasm_std::Order::Ascending)
                .count(),
            verifiers.len()
        );
    }
}
