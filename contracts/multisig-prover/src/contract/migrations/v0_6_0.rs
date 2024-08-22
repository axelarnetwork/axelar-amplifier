#![allow(deprecated)]

use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::hash::Hash;
use axelar_wasm_std::{permission_control, MajorityThreshold};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Storage};
use cw_storage_plus::Item;
use multisig::key::KeyType;
use router_api::ChainName;

use crate::contract::{CONTRACT_NAME, CONTRACT_VERSION};
use crate::encoding::Encoder;
use crate::state;

const BASE_VERSION: &str = "0.6.0";

pub fn migrate(storage: &mut dyn Storage) -> Result<(), ContractError> {
    cw2::assert_contract_version(storage, CONTRACT_NAME, BASE_VERSION)?;

    let config = CONFIG.load(storage)?;

    migrate_permission_control(storage, &config)?;
    migrate_config(storage, config)?;
    delete_payloads(storage);

    cw2::set_contract_version(storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(())
}

fn delete_payloads(storage: &mut dyn Storage) {
    state::PAYLOAD.clear(storage);
    state::MULTISIG_SESSION_PAYLOAD.clear(storage);
    state::REPLY_TRACKER.remove(storage);
}

fn migrate_permission_control(
    storage: &mut dyn Storage,
    config: &Config,
) -> Result<(), ContractError> {
    permission_control::set_governance(storage, &config.governance)?;
    permission_control::set_admin(storage, &config.admin)?;
    Ok(())
}

fn migrate_config(storage: &mut dyn Storage, config: Config) -> Result<(), ContractError> {
    CONFIG.remove(storage);

    let config = state::Config {
        gateway: config.gateway,
        multisig: config.multisig,
        coordinator: config.coordinator,
        service_registry: config.service_registry,
        voting_verifier: config.voting_verifier,
        signing_threshold: config.signing_threshold,
        service_name: config.service_name,
        chain_name: config.chain_name,
        verifier_set_diff_threshold: config.verifier_set_diff_threshold,
        encoder: config.encoder,
        key_type: config.key_type,
        domain_separator: config.domain_separator,
    };
    state::CONFIG.save(storage, &config)?;
    Ok(())
}

#[cw_serde]
#[deprecated(since = "0.6.0", note = "only used during migration")]
struct Config {
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
    pub verifier_set_diff_threshold: u32,
    pub encoder: Encoder,
    pub key_type: KeyType,
    pub domain_separator: Hash,
}
#[deprecated(since = "0.6.0", note = "only used during migration")]
const CONFIG: Item<Config> = Item::new("config");

#[cfg(test)]
mod tests {
    use axelar_wasm_std::permission_control::Permission;
    use axelar_wasm_std::{permission_control, MajorityThreshold, Threshold};
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{Addr, DepsMut, Env, MessageInfo, Response};
    use multisig::key::KeyType;
    use router_api::{CrossChainId, Message};

    use crate::contract::migrations::v0_6_0;
    use crate::contract::{CONTRACT_NAME, CONTRACT_VERSION};
    use crate::encoding::Encoder;
    use crate::error::ContractError;
    use crate::msg::InstantiateMsg;
    use crate::{payload, state};

    #[test]
    fn migrate_checks_contract_version() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());
        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, "something wrong").unwrap();

        assert!(v0_6_0::migrate(deps.as_mut().storage).is_err());

        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, v0_6_0::BASE_VERSION)
            .unwrap();

        assert!(v0_6_0::migrate(deps.as_mut().storage).is_ok());
    }

    #[test]
    fn migrate_sets_contract_version() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());

        v0_6_0::migrate(deps.as_mut().storage).unwrap();

        let contract_version = cw2::get_contract_version(deps.as_mut().storage).unwrap();
        assert_eq!(contract_version.contract, CONTRACT_NAME);
        assert_eq!(contract_version.version, CONTRACT_VERSION);
    }

    #[test]
    fn migrate_payload() {
        let mut deps = mock_dependencies();

        instantiate_contract(deps.as_mut());

        let msgs = vec![
            Message {
                cc_id: CrossChainId {
                    message_id: "id1".try_into().unwrap(),
                    source_chain: "chain1".try_into().unwrap(),
                },
                source_address: "source-address".parse().unwrap(),
                destination_chain: "destination".parse().unwrap(),
                destination_address: "destination-address".parse().unwrap(),
                payload_hash: [1; 32],
            },
            Message {
                cc_id: CrossChainId {
                    message_id: "id2".try_into().unwrap(),
                    source_chain: "chain2".try_into().unwrap(),
                },
                source_address: "source-address2".parse().unwrap(),
                destination_chain: "destination2".parse().unwrap(),
                destination_address: "destination-address2".parse().unwrap(),
                payload_hash: [2; 32],
            },
            Message {
                cc_id: CrossChainId {
                    message_id: "id3".try_into().unwrap(),
                    source_chain: "chain3".try_into().unwrap(),
                },
                source_address: "source-address3".parse().unwrap(),
                destination_chain: "destination3".parse().unwrap(),
                destination_address: "destination-address3".parse().unwrap(),
                payload_hash: [3; 32],
            },
        ];

        let payload = payload::Payload::Messages(msgs);

        state::PAYLOAD
            .save(deps.as_mut().storage, &payload.id(), &payload)
            .unwrap();

        assert!(v0_6_0::migrate(deps.as_mut().storage).is_ok());

        assert!(state::PAYLOAD.is_empty(deps.as_ref().storage));
    }

    #[test]
    fn migrate_permission_control() {
        let mut deps = mock_dependencies();

        instantiate_contract(deps.as_mut());

        assert!(v0_6_0::migrate(deps.as_mut().storage).is_ok());

        assert_eq!(
            permission_control::sender_role(deps.as_ref().storage, &Addr::unchecked("admin"))
                .unwrap(),
            Permission::Admin.into()
        );

        assert_eq!(
            permission_control::sender_role(deps.as_ref().storage, &Addr::unchecked("governance"))
                .unwrap(),
            Permission::Governance.into()
        );
    }

    #[test]
    fn migrate_config() {
        let mut deps = mock_dependencies();

        instantiate_contract(deps.as_mut());

        assert!(v0_6_0::CONFIG.load(deps.as_ref().storage).is_ok());
        assert!(state::CONFIG.load(deps.as_ref().storage).is_err());

        assert!(v0_6_0::migrate(deps.as_mut().storage).is_ok());

        assert!(v0_6_0::CONFIG.load(deps.as_ref().storage).is_err());
        assert!(state::CONFIG.load(deps.as_ref().storage).is_ok());
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
        cw2::set_contract_version(deps.storage, CONTRACT_NAME, v0_6_0::BASE_VERSION)?;

        let config = make_config(&deps, msg)?;
        v0_6_0::CONFIG.save(deps.storage, &config)?;

        Ok(Response::default())
    }

    fn make_config(
        deps: &DepsMut,
        msg: InstantiateMsg,
    ) -> Result<v0_6_0::Config, axelar_wasm_std::error::ContractError> {
        let admin = deps.api.addr_validate(&msg.admin_address)?;
        let governance = deps.api.addr_validate(&msg.governance_address)?;
        let gateway = deps.api.addr_validate(&msg.gateway_address)?;
        let multisig = deps.api.addr_validate(&msg.multisig_address)?;
        let coordinator = deps.api.addr_validate(&msg.coordinator_address)?;
        let service_registry = deps.api.addr_validate(&msg.service_registry_address)?;
        let voting_verifier = deps.api.addr_validate(&msg.voting_verifier_address)?;

        Ok(v0_6_0::Config {
            admin,
            governance,
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
