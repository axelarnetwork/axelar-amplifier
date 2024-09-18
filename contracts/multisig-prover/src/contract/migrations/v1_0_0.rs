#![allow(deprecated)]

use axelar_wasm_std::error::ContractError;
use cosmwasm_std::{wasm_execute, Response, Storage};

use crate::contract::execute::all_active_verifiers;
use crate::contract::CONTRACT_NAME;
use crate::state::CONFIG;

const BASE_VERSION: &str = "1.0.0";

pub fn migrate(storage: &mut dyn Storage) -> Result<Response, ContractError> {
    cw2::assert_contract_version(storage, CONTRACT_NAME, BASE_VERSION)?;
    let config = CONFIG.load(storage)?;

    let verifiers = all_active_verifiers(storage)?;

    Ok(Response::new().add_message(
        wasm_execute(
            config.coordinator,
            &coordinator::msg::ExecuteMsg::SetActiveVerifiers { verifiers },
            vec![],
        )
        .map_err(ContractError::from)?,
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use axelar_wasm_std::{MajorityThreshold, Threshold};
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{
        from_json, CosmosMsg, DepsMut, Env, MessageInfo, Response, SubMsg, WasmMsg,
    };
    use multisig::key::KeyType;

    use crate::contract::migrations::v1_0_0;
    use crate::contract::{CONTRACT_NAME, CONTRACT_VERSION};
    use crate::encoding::Encoder;
    use crate::error::ContractError;
    use crate::msg::InstantiateMsg;
    use crate::state::{Config, CURRENT_VERIFIER_SET, NEXT_VERIFIER_SET};
    use crate::test::test_data;
    use crate::test::test_utils::COORDINATOR_ADDRESS;

    #[test]
    fn migrate_checks_contract_version() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());
        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, "something wrong").unwrap();

        assert!(v1_0_0::migrate(deps.as_mut().storage).is_err());

        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, v1_0_0::BASE_VERSION)
            .unwrap();

        assert!(v1_0_0::migrate(deps.as_mut().storage).is_ok());
    }

    #[test]
    fn migrate_sets_contract_version() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());

        v1_0_0::migrate(deps.as_mut().storage).unwrap();

        let contract_version = cw2::get_contract_version(deps.as_mut().storage).unwrap();
        assert_eq!(contract_version.contract, CONTRACT_NAME);
        assert_eq!(contract_version.version, CONTRACT_VERSION);
    }

    // returns None if the msg is not the expected type (coordinator::msg::ExecuteMsg::SetActiveVerifiers)
    fn extract_verifiers_from_set_active_verifiers_msg(msg: SubMsg) -> Option<HashSet<String>> {
        match msg.msg {
            CosmosMsg::Wasm(WasmMsg::Execute { msg, .. }) => {
                let msg: coordinator::msg::ExecuteMsg = from_json(msg).unwrap();
                match msg {
                    coordinator::msg::ExecuteMsg::SetActiveVerifiers { verifiers } => {
                        Some(verifiers)
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    // returns None if the msg is not the expected type (WasmMsg::Execute)
    fn extract_contract_address_from_wasm_msg(msg: SubMsg) -> Option<String> {
        match msg.msg {
            CosmosMsg::Wasm(WasmMsg::Execute { contract_addr, .. }) => Some(contract_addr),
            _ => None,
        }
    }

    #[test]
    fn migrate_sets_active_verifiers() {
        let mut deps = mock_dependencies();

        instantiate_contract(deps.as_mut());
        CURRENT_VERIFIER_SET
            .save(deps.as_mut().storage, &test_data::curr_verifier_set())
            .unwrap();

        let res = v1_0_0::migrate(deps.as_mut().storage);
        assert!(res.is_ok());

        let msgs = res.unwrap().messages;
        assert_eq!(msgs.len(), 1);
        let msg = msgs[0].clone();

        let contract_address = extract_contract_address_from_wasm_msg(msg.clone());
        assert!(contract_address.is_some());
        assert_eq!(COORDINATOR_ADDRESS, contract_address.unwrap());

        let verifiers = extract_verifiers_from_set_active_verifiers_msg(msg);
        assert!(verifiers.is_some());

        assert_eq!(
            verifiers.unwrap(),
            test_data::curr_verifier_set()
                .signers
                .values()
                .map(|signer| signer.address.to_string())
                .collect::<HashSet<String>>()
        );
    }

    #[test]
    fn migrate_sets_active_verifiers_when_rotation_in_progress() {
        let mut deps = mock_dependencies();

        instantiate_contract(deps.as_mut());
        CURRENT_VERIFIER_SET
            .save(deps.as_mut().storage, &test_data::curr_verifier_set())
            .unwrap();

        NEXT_VERIFIER_SET
            .save(deps.as_mut().storage, &test_data::new_verifier_set())
            .unwrap();

        let res = v1_0_0::migrate(deps.as_mut().storage);
        assert!(res.is_ok());

        let msgs = res.unwrap().messages;
        assert_eq!(msgs.len(), 1);
        let msg = msgs[0].clone();

        let contract_address = extract_contract_address_from_wasm_msg(msg.clone());
        assert!(contract_address.is_some());
        assert_eq!(COORDINATOR_ADDRESS, contract_address.unwrap());

        let verifiers = extract_verifiers_from_set_active_verifiers_msg(msg);
        assert!(verifiers.is_some());

        assert_eq!(
            verifiers.unwrap(),
            test_data::curr_verifier_set()
                .signers
                .values()
                .chain(test_data::new_verifier_set().signers.values())
                .map(|signer| signer.address.to_string())
                .collect::<HashSet<String>>()
        );
    }

    fn instantiate_contract(deps: DepsMut) {
        instantiate(
            deps,
            mock_env(),
            mock_info("admin", &[]),
            InstantiateMsg {
                admin_address: "admin".to_string(),
                governance_address: "governance".to_string(),
                gateway_address: "gateway".to_string(),
                multisig_address: "multisig".to_string(),
                coordinator_address: "coordinator".to_string(),
                service_registry_address: "service_registry".to_string(),
                voting_verifier_address: "voting_verifier".to_string(),
                signing_threshold: Threshold::try_from((2u64, 3u64))
                    .and_then(MajorityThreshold::try_from)
                    .unwrap(),
                service_name: "service".to_string(),
                chain_name: "chain".to_string(),
                verifier_set_diff_threshold: 1,
                encoder: Encoder::Abi,
                key_type: KeyType::Ecdsa,
                domain_separator: [0; 32],
            },
        )
        .unwrap();
    }

    #[deprecated(since = "0.6.0", note = "only used to test the migration")]
    pub fn instantiate(
        deps: DepsMut,
        _env: Env,
        _info: MessageInfo,
        msg: InstantiateMsg,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        cw2::set_contract_version(deps.storage, CONTRACT_NAME, v1_0_0::BASE_VERSION)?;

        let config = make_config(&deps, msg)?;
        v1_0_0::CONFIG.save(deps.storage, &config)?;

        Ok(Response::default())
    }

    fn make_config(
        deps: &DepsMut,
        msg: InstantiateMsg,
    ) -> Result<Config, axelar_wasm_std::error::ContractError> {
        let gateway = deps.api.addr_validate(&msg.gateway_address)?;
        let multisig = deps.api.addr_validate(&msg.multisig_address)?;
        let coordinator = deps.api.addr_validate(&msg.coordinator_address)?;
        let service_registry = deps.api.addr_validate(&msg.service_registry_address)?;
        let voting_verifier = deps.api.addr_validate(&msg.voting_verifier_address)?;

        Ok(Config {
            gateway,
            multisig,
            coordinator,
            service_registry,
            voting_verifier,
            signing_threshold: msg.signing_threshold,
            service_name: msg.service_name,
            chain_name: msg
                .chain_name
                .parse()
                .map_err(|_| ContractError::InvalidChainName)?,
            verifier_set_diff_threshold: msg.verifier_set_diff_threshold,
            encoder: msg.encoder,
            key_type: msg.key_type,
            domain_separator: msg.domain_separator,
        })
    }
}
