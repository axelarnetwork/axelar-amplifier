use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, DepsMut, Response};
use cw_storage_plus::Item;

use axelar_wasm_std::{nonempty, MajorityThreshold};
use connection_router_api::ChainName;

use crate::{
    contract::{CONTRACT_NAME, CONTRACT_VERSION},
    error::ContractError,
    state::{Config, CONFIG},
};

pub const EXPECTED_FROM_VERSION: &str = "0.1.0";

mod v0_1_0_state {
    use super::*;

    #[cw_serde]
    pub struct Config {
        pub service_registry_contract: Addr,
        pub service_name: nonempty::String,
        pub source_gateway_address: nonempty::String,
        pub voting_threshold: MajorityThreshold,
        pub block_expiry: u64,
        pub confirmation_height: u64,
        pub source_chain: ChainName,
        pub rewards_contract: Addr,
    }

    pub const CONFIG: Item<Config> = Item::new("config");
}

pub fn migrate(deps: DepsMut, governance_address: String) -> Result<Response, ContractError> {
    let governance = deps.api.addr_validate(&governance_address)?;

    let old_config = v0_1_0_state::CONFIG.load(deps.storage)?;

    let new_config = Config {
        governance,

        // copy over all fields
        service_registry_contract: old_config.service_registry_contract,
        service_name: old_config.service_name,
        source_gateway_address: old_config.source_gateway_address,
        voting_threshold: old_config.voting_threshold,
        block_expiry: old_config.block_expiry,
        confirmation_height: old_config.confirmation_height,
        source_chain: old_config.source_chain,
        rewards_contract: old_config.rewards_contract,
    };
    CONFIG.save(deps.storage, &new_config)?;

    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::new()
        .add_attribute("action", "migrate")
        .add_attribute("from_version", EXPECTED_FROM_VERSION)
        .add_attribute("to_version", CONTRACT_VERSION)
        .add_attribute("governance_address", governance_address))
}

#[cfg(test)]
mod test {
    use cosmwasm_std::{testing::mock_dependencies, Addr};

    use axelar_wasm_std::Threshold;

    use super::{migrate, v0_1_0_state};

    #[test]
    fn migration() {
        let mut deps = mock_dependencies();

        // set up old state
        v0_1_0_state::CONFIG
            .save(
                &mut deps.storage,
                &v0_1_0_state::Config {
                    service_registry_contract: Addr::unchecked("service_registry"),
                    service_name: "service_name".parse().unwrap(),
                    source_gateway_address: "source_gateway_address".parse().unwrap(),
                    voting_threshold: Threshold::try_from((2, 3)).unwrap().try_into().unwrap(),
                    block_expiry: 100,
                    confirmation_height: 10,
                    source_chain: "test-chain".parse().unwrap(),
                    rewards_contract: Addr::unchecked("rewards_contract"),
                },
            )
            .unwrap();

        let res = migrate(deps.as_mut(), "governance_address".to_string()).unwrap();
        assert_eq!(
            res.attributes[3],
            ("governance_address", "governance_address")
        );

        // load the new state
        let config = crate::state::CONFIG.load(&deps.storage).unwrap();
        assert_eq!(config.governance, Addr::unchecked("governance_address"));
    }
}
