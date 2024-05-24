use axelar_wasm_std::{hash::Hash, FnExt, MajorityThreshold};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{from_json, Addr, DepsMut, Response};
use cw_storage_plus::Item;
use multisig::{key::KeyType, verifier_set::VerifierSet};
use router_api::ChainName;

use crate::{
    encoding::Encoder,
    state::{Config, CONFIG, CURRENT_VERIFIER_SET, NEXT_VERIFIER_SET},
};

const CURRENT_WORKER_SET: Item<VerifierSet> = Item::new("current_worker_set");
const NEXT_WORKER_SET: Item<VerifierSet> = Item::new("next_worker_set");

#[cw_serde]
pub struct OldConfig {
    pub admin: Addr,
    pub governance: Addr,
    pub gateway: Addr,
    pub multisig: Addr,
    pub coordinator: Addr,
    pub service_registry: Addr,
    pub voting_verifier: Addr,
    pub signing_threshold: MajorityThreshold,
    pub service_name: String,
    pub chain_name: ChainName,
    pub worker_set_diff_threshold: u32,
    pub encoder: Encoder,
    pub key_type: KeyType,
    pub domain_separator: Hash,
}
impl OldConfig {
    pub fn migrate(self) -> Config {
        Config {
            domain_separator: self.domain_separator,
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
            verifier_set_diff_threshold: self.worker_set_diff_threshold,
            encoder: self.encoder,
            key_type: self.key_type,
        }
    }
}

pub fn migrate_verifier_sets(deps: DepsMut) -> Result<Response, axelar_wasm_std::ContractError> {
    let old_config: OldConfig = deps
        .storage
        .get(CONFIG.as_slice())
        .expect("config not found")
        .then(from_json)?;

    let new_config = old_config.migrate();
    CONFIG.save(deps.storage, &new_config)?;
    let current_worker_set = CURRENT_WORKER_SET.may_load(deps.storage)?;
    if let Some(current_worker_set) = current_worker_set {
        CURRENT_WORKER_SET.remove(deps.storage);
        CURRENT_VERIFIER_SET.save(deps.storage, &current_worker_set)?;
    }

    let next_worker_set = NEXT_WORKER_SET.may_load(deps.storage)?;
    if let Some(next_worker_set) = next_worker_set {
        NEXT_WORKER_SET.remove(deps.storage);
        NEXT_VERIFIER_SET.save(deps.storage, &next_worker_set)?;
    }

    Ok(Response::default())
}

#[cfg(test)]
mod test {
    use crate::{
        migrations::v_0_5::{OldConfig, NEXT_WORKER_SET},
        state::{CONFIG, CURRENT_VERIFIER_SET, NEXT_VERIFIER_SET},
        test::test_data::new_verifier_set,
    };

    use axelar_wasm_std::Threshold;
    use cosmwasm_std::{testing::mock_dependencies, to_json_vec, Addr, Uint128};

    use super::{migrate_verifier_sets, CURRENT_WORKER_SET};

    #[test]
    fn should_be_able_to_migrate_worker_set_to_verifier_set() {
        let mut deps = mock_dependencies();

        let initial_config = OldConfig {
            admin: Addr::unchecked("admin"),
            governance: Addr::unchecked("governance"),
            gateway: Addr::unchecked("gateway"),
            multisig: Addr::unchecked("multisig"),
            coordinator: Addr::unchecked("coordinator"),
            service_registry: Addr::unchecked("service_registry"),
            voting_verifier: Addr::unchecked("voting_verifier"),
            signing_threshold: Threshold::try_from((2, 3)).unwrap().try_into().unwrap(),
            service_name: "validators".to_string(),
            chain_name: "ganache-0".parse().unwrap(),
            worker_set_diff_threshold: 0,
            encoder: crate::encoding::Encoder::Abi,
            key_type: multisig::key::KeyType::Ecdsa,
            domain_separator: [1; 32],
        };
        deps.as_mut()
            .storage
            .set(CONFIG.as_slice(), &to_json_vec(&initial_config).unwrap());

        let worker_set = new_verifier_set();

        CURRENT_WORKER_SET
            .save(&mut deps.storage, &worker_set)
            .unwrap();

        let res = migrate_verifier_sets(deps.as_mut());
        assert!(res.is_ok());

        let verifier_set = CURRENT_VERIFIER_SET.load(&deps.storage).unwrap();
        assert_eq!(verifier_set, worker_set);

        assert!(NEXT_VERIFIER_SET.may_load(&deps.storage).unwrap().is_none());

        assert!(CURRENT_WORKER_SET
            .may_load(&deps.storage)
            .unwrap()
            .is_none());

        assert!(NEXT_WORKER_SET.may_load(&deps.storage).unwrap().is_none());
    }

    #[test]
    fn should_be_able_to_migrate_worker_set_to_verifier_set_mid_rotation() {
        let mut deps = mock_dependencies();
        let initial_config = OldConfig {
            admin: Addr::unchecked("admin"),
            governance: Addr::unchecked("governance"),
            gateway: Addr::unchecked("gateway"),
            multisig: Addr::unchecked("multisig"),
            coordinator: Addr::unchecked("coordinator"),
            service_registry: Addr::unchecked("service_registry"),
            voting_verifier: Addr::unchecked("voting_verifier"),
            signing_threshold: Threshold::try_from((2, 3)).unwrap().try_into().unwrap(),
            service_name: "validators".to_string(),
            chain_name: "ganache-0".parse().unwrap(),
            worker_set_diff_threshold: 0,
            encoder: crate::encoding::Encoder::Abi,
            key_type: multisig::key::KeyType::Ecdsa,
            domain_separator: [1; 32],
        };
        deps.as_mut()
            .storage
            .set(CONFIG.as_slice(), &to_json_vec(&initial_config).unwrap());

        let worker_set = new_verifier_set();

        CURRENT_WORKER_SET
            .save(&mut deps.storage, &worker_set)
            .unwrap();

        let mut next_worker_set = worker_set.clone();
        next_worker_set.threshold = worker_set.threshold.checked_add(Uint128::one()).unwrap();
        NEXT_WORKER_SET
            .save(&mut deps.storage, &next_worker_set)
            .unwrap();

        let res = migrate_verifier_sets(deps.as_mut());
        assert!(res.is_ok());

        let verifier_set = CURRENT_VERIFIER_SET.load(&deps.storage).unwrap();
        assert_eq!(verifier_set, worker_set);

        let next_verifier_set = NEXT_VERIFIER_SET.load(&deps.storage).unwrap();
        assert_eq!(next_verifier_set, next_worker_set);

        assert!(CURRENT_WORKER_SET
            .may_load(&deps.storage)
            .unwrap()
            .is_none());
        assert!(NEXT_WORKER_SET.may_load(&deps.storage).unwrap().is_none());
    }
}
