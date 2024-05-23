//! Migrate the `Config` to include `msg_id_format` field and replace source_gateway_address value.

use axelar_wasm_std::{msg_id::MessageIdFormat, nonempty, FnExt, MajorityThreshold};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{from_json, Addr, DepsMut, Response};
use router_api::ChainName;

use crate::state::{Config, CONFIG};

#[cw_serde]
pub struct OldConfig {
    pub governance: Addr,
    pub service_registry_contract: Addr,
    pub service_name: nonempty::String,
    pub source_gateway_address: nonempty::String,
    pub voting_threshold: MajorityThreshold,
    pub block_expiry: u64,
    pub confirmation_height: u64,
    pub source_chain: ChainName,
    pub rewards_contract: Addr,
}

impl OldConfig {
    pub fn migrate(
        self,
        source_gateway_address: nonempty::String,
        msg_id_format: MessageIdFormat,
    ) -> Config {
        Config {
            source_gateway_address,
            msg_id_format,
            governance: self.governance,
            service_registry_contract: self.service_registry_contract,
            service_name: self.service_name,
            voting_threshold: self.voting_threshold,
            block_expiry: self.block_expiry,
            confirmation_height: self.confirmation_height,
            source_chain: self.source_chain,
            rewards_contract: self.rewards_contract,
        }
    }
}

pub fn migrate_config(
    deps: DepsMut,
    source_gateway_address: nonempty::String,
    msg_id_format: MessageIdFormat,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let old_config: OldConfig = deps
        .storage
        .get(CONFIG.as_slice())
        .expect("config not found")
        .then(from_json)?;

    let new_config = old_config.migrate(source_gateway_address, msg_id_format);
    CONFIG.save(deps.storage, &new_config)?;

    Ok(Response::default())
}

#[cfg(test)]
mod test {

    use axelar_wasm_std::{msg_id::MessageIdFormat, Threshold};
    use cosmwasm_std::{testing::mock_dependencies, to_json_vec, Addr};

    use super::*;

    #[test]
    fn successfuly_migrate_source_gateway_address() {
        let mut deps = mock_dependencies();

        let initial_config = OldConfig {
            governance: Addr::unchecked("governance"),
            service_name: "service_name".parse().unwrap(),
            service_registry_contract: Addr::unchecked("service_registry_address"),
            source_gateway_address: "initial_source_gateway_address".parse().unwrap(),
            voting_threshold: Threshold::try_from((2, 3)).unwrap().try_into().unwrap(),
            block_expiry: 100,
            confirmation_height: 100,
            source_chain: "source-chain".parse().unwrap(),
            rewards_contract: Addr::unchecked("rewards_address"),
        };
        deps.as_mut()
            .storage
            .set(CONFIG.as_slice(), &to_json_vec(&initial_config).unwrap());

        let new_source_gateway_address: nonempty::String =
            "new_source_gateway_address".parse().unwrap();
        let msg_id_format = MessageIdFormat::HexTxHashAndEventIndex;
        let response = migrate_config(
            deps.as_mut(),
            new_source_gateway_address.clone(),
            msg_id_format.clone(),
        )
        .unwrap();

        assert_eq!(response, Response::default());

        let actual_config = CONFIG.load(deps.as_ref().storage).unwrap();
        let expected_config = Config {
            governance: initial_config.governance,
            service_registry_contract: initial_config.service_registry_contract,
            service_name: initial_config.service_name,
            source_gateway_address: new_source_gateway_address,
            voting_threshold: initial_config.voting_threshold,
            block_expiry: initial_config.block_expiry,
            confirmation_height: initial_config.confirmation_height,
            source_chain: initial_config.source_chain,
            rewards_contract: initial_config.rewards_contract,
            msg_id_format,
        };

        assert_eq!(actual_config, expected_config)
    }
}
