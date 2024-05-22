//! Migrate the `Config` to include `domain_separator` field and remove `destination_chain_id` field.

use axelar_wasm_std::{hash::Hash, FnExt, MajorityThreshold};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{from_json, Addr, DepsMut, Response, Uint256};
use multisig::key::KeyType;
use router_api::ChainName;

use crate::{
    encoding::Encoder,
    state::{Config, CONFIG},
};

#[cw_serde]
pub struct OldConfig {
    pub admin: Addr,
    pub governance: Addr,
    pub gateway: Addr,
    pub multisig: Addr,
    pub coordinator: Addr,
    pub service_registry: Addr,
    pub voting_verifier: Addr,
    pub destination_chain_id: Uint256, // this field is removed during migration
    pub signing_threshold: MajorityThreshold,
    pub service_name: String,
    pub chain_name: ChainName,
    pub worker_set_diff_threshold: u32,
    pub encoder: Encoder,
    pub key_type: KeyType,
}

impl OldConfig {
    pub fn migrate(self, domain_separator: Hash) -> Config {
        Config {
            domain_separator,
            admin: self.admin,
            governance: self.governance,
            gateway: self.gateway,
            multisig: self.multisig,
            coordinator: self.coordinator,
            service_registry: self.service_registry,
            voting_verifier: self.voting_verifier,
            signing_threshold: self.signing_threshold,
            service_name: self.service_name,
            chain_name: self.chain_name,
            worker_set_diff_threshold: self.worker_set_diff_threshold,
            encoder: self.encoder,
            key_type: self.key_type,
        }
    }
}

pub fn migrate_config(
    deps: DepsMut,
    domain_separator: Hash,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let old_config: OldConfig = deps
        .storage
        .get(CONFIG.as_slice())
        .expect("config not found")
        .then(from_json)?;

    let new_config = old_config.migrate(domain_separator);
    CONFIG.save(deps.storage, &new_config)?;

    Ok(Response::default())
}

#[cfg(test)]
mod test {

    use axelar_wasm_std::Threshold;
    use cosmwasm_std::{testing::mock_dependencies, to_json_vec, Addr, Uint256};

    use super::*;

    #[test]
    fn successfuly_migrate_domain_separator() {
        let mut deps = mock_dependencies();

        let initial_config = OldConfig {
            admin: Addr::unchecked("admin"),
            governance: Addr::unchecked("governance"),
            gateway: Addr::unchecked("gateway"),
            multisig: Addr::unchecked("multisig"),
            coordinator: Addr::unchecked("coordinator"),
            service_registry: Addr::unchecked("service_registry"),
            voting_verifier: Addr::unchecked("voting_verifier"),
            destination_chain_id: Uint256::from(1337u128),
            signing_threshold: Threshold::try_from((2, 3)).unwrap().try_into().unwrap(),
            service_name: "validators".to_string(),
            chain_name: "ganache-0".parse().unwrap(),
            worker_set_diff_threshold: 0,
            encoder: crate::encoding::Encoder::Abi,
            key_type: multisig::key::KeyType::Ecdsa,
        };
        deps.as_mut()
            .storage
            .set(CONFIG.as_slice(), &to_json_vec(&initial_config).unwrap());

        let domain_separator = [1; 32];
        let response = migrate_config(deps.as_mut(), domain_separator).unwrap();

        assert_eq!(response, Response::default());

        let actual_config = CONFIG.load(deps.as_ref().storage).unwrap();
        let expected_config = Config {
            admin: initial_config.admin,
            governance: initial_config.governance,
            gateway: initial_config.gateway,
            multisig: initial_config.multisig,
            coordinator: initial_config.coordinator,
            service_registry: initial_config.service_registry,
            voting_verifier: initial_config.voting_verifier,
            signing_threshold: initial_config.signing_threshold,
            service_name: initial_config.service_name,
            chain_name: initial_config.chain_name,
            worker_set_diff_threshold: initial_config.worker_set_diff_threshold,
            encoder: initial_config.encoder,
            key_type: initial_config.key_type,
            domain_separator,
        };
        assert_eq!(actual_config, expected_config)
    }
}
