//! Migrate the `Service` struct and rename `service_contract` field to `coordinator_contract`.

use cosmwasm_std::{Addr, Order, Response, Storage};

use crate::state::{Service, SERVICES};

mod v0_3_state {
    use cosmwasm_schema::cw_serde;
    use cosmwasm_std::{Addr, Uint128};
    use cw_storage_plus::Map;

    #[cw_serde]
    pub struct Service {
        pub name: String,
        pub service_contract: Addr,
        pub min_num_verifiers: u16,
        pub max_num_verifiers: Option<u16>,
        pub min_verifier_bond: Uint128,
        pub bond_denom: String,
        pub unbonding_period_days: u16,
        pub description: String,
    }

    type ServiceName = str;
    pub const SERVICES: Map<&ServiceName, Service> = Map::new("services");
}

pub fn migrate_services_coordinator_contract(
    store: &mut dyn Storage,
    coordinator_contract: Addr,
) -> Result<Response, axelar_wasm_std::ContractError> {
    v0_3_state::SERVICES
        .range(store, None, None, Order::Ascending)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|(service_name, service)| {
            let service = Service {
                name: service.name,
                coordinator_contract: coordinator_contract.clone(),
                min_num_verifiers: service.min_num_verifiers,
                max_num_verifiers: service.max_num_verifiers,
                min_verifier_bond: service.min_verifier_bond,
                bond_denom: service.bond_denom,
                unbonding_period_days: service.unbonding_period_days,
                description: service.description,
            };
            SERVICES.save(store, &service_name, &service)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Response::default())
}

#[cfg(test)]
mod test {
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::{Addr, Uint128};

    use super::*;

    #[test]
    fn successfully_migrate_services() {
        let mut deps = mock_dependencies();

        let initial_services = vec![
            v0_3_state::Service {
                name: "service1".to_string(),
                service_contract: Addr::unchecked("service_contract1"),
                min_num_verifiers: 5,
                max_num_verifiers: Some(10),
                min_verifier_bond: Uint128::from(1000u128),
                bond_denom: "denom1".to_string(),
                unbonding_period_days: 7,
                description: "description1".to_string(),
            },
            v0_3_state::Service {
                name: "service2".to_string(),
                service_contract: Addr::unchecked("service_contract2"),
                min_num_verifiers: 3,
                max_num_verifiers: None,
                min_verifier_bond: Uint128::from(2000u128),
                bond_denom: "denom2".to_string(),
                unbonding_period_days: 14,
                description: "description2".to_string(),
            },
        ];

        for service in &initial_services {
            v0_3_state::SERVICES
                .save(&mut deps.storage, service.name.as_str(), service)
                .unwrap();
        }

        let coordinator_contract = Addr::unchecked("coordinator");
        migrate_services_coordinator_contract(&mut deps.storage, coordinator_contract.clone())
            .unwrap();

        for service in &initial_services {
            let migrated_service: Service =
                SERVICES.load(&deps.storage, service.name.as_str()).unwrap();

            let expected_service = Service {
                name: service.name.clone(),
                coordinator_contract: coordinator_contract.clone(),
                min_num_verifiers: service.min_num_verifiers,
                max_num_verifiers: service.max_num_verifiers,
                min_verifier_bond: service.min_verifier_bond,
                bond_denom: service.bond_denom.clone(),
                unbonding_period_days: service.unbonding_period_days,
                description: service.description.clone(),
            };

            assert_eq!(migrated_service, expected_service);
        }
    }
}
