use axelar_wasm_std::hash::Hash;
use cosmwasm_std::{DepsMut, Response};

use crate::state::{Config, CONFIG};

pub fn set_domain_separator(
    deps: DepsMut,
    domain_separator: Hash,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let old_config = CONFIG.load(deps.storage)?;
    let new_config = Config {
        domain_separator,
        ..old_config
    };
    CONFIG.save(deps.storage, &new_config)?;

    Ok(Response::default())
}

#[cfg(test)]
mod test {

    use axelar_wasm_std::Threshold;
    use cosmwasm_std::{testing::mock_dependencies, Addr, Uint256};

    use super::*;

    #[test]
    fn successfuly_migrate_domain_separator() {
        let mut deps = mock_dependencies();

        let initial_config = Config {
            admin: Addr::unchecked("admin"),
            governance: Addr::unchecked("governance"),
            gateway: Addr::unchecked("gateway"),
            multisig: Addr::unchecked("multisig"),
            coordinator: Addr::unchecked("coordinator"),
            service_registry: Addr::unchecked("service_registry"),
            voting_verifier: Addr::unchecked("voting_verifier"),
            destination_chain_id: Uint256::from(1337u128),
            signing_threshold: Threshold::try_from((2u64, 3u64))
                .unwrap()
                .try_into()
                .unwrap(),
            service_name: "validators".to_string(),
            chain_name: "ganache-0".parse().unwrap(),
            worker_set_diff_threshold: 0,
            encoder: crate::encoding::Encoder::Abi,
            key_type: multisig::key::KeyType::Ecdsa,
            domain_separator: [0; 32],
        };
        CONFIG.save(deps.as_mut().storage, &initial_config).unwrap();

        let new_domain_separator = [1; 32];
        let response = set_domain_separator(deps.as_mut(), new_domain_separator.clone()).unwrap();

        assert_eq!(response, Response::default());

        let actual_config = CONFIG.load(deps.as_ref().storage).unwrap();
        assert_eq!(
            actual_config,
            Config {
                domain_separator: new_domain_separator,
                ..initial_config
            }
        )
    }
}
