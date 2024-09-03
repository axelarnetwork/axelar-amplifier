#![allow(deprecated)]

use axelar_wasm_std::address::AddressFormat;
use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::msg_id::MessageIdFormat;
use axelar_wasm_std::{nonempty, permission_control, MajorityThreshold};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Attribute, StdResult, Storage};
use cw_storage_plus::Item;
use router_api::ChainName;

use crate::contract::{CONTRACT_NAME, CONTRACT_VERSION};
use crate::state;

const BASE_VERSION: &str = "0.5.0";

pub fn migrate(storage: &mut dyn Storage) -> Result<(), ContractError> {
    cw2::assert_contract_version(storage, CONTRACT_NAME, BASE_VERSION)?;

    let config = CONFIG.load(storage)?;
    migrate_permission_control(storage, &config.governance)?;
    migrate_config(storage, config)?;

    delete_polls(storage);

    cw2::set_contract_version(storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(())
}

fn migrate_config(storage: &mut dyn Storage, config: Config) -> StdResult<()> {
    CONFIG.remove(storage);

    let config = state::Config {
        service_registry_contract: config.service_registry_contract,
        service_name: config.service_name,
        source_chain: config.source_chain,
        rewards_contract: config.rewards_contract,
        block_expiry: config
            .block_expiry
            .try_into()
            .unwrap_or(1.try_into().expect("1 is not zero")),
        confirmation_height: config.confirmation_height,
        msg_id_format: config.msg_id_format,
        source_gateway_address: config.source_gateway_address,
        voting_threshold: config.voting_threshold,
        address_format: AddressFormat::Eip55,
    };

    state::CONFIG.save(storage, &config)
}

fn migrate_permission_control(storage: &mut dyn Storage, governance: &Addr) -> StdResult<()> {
    permission_control::set_governance(storage, governance)
}

fn delete_polls(storage: &mut dyn Storage) {
    state::POLLS.clear(storage);
    state::VOTES.clear(storage);
    state::poll_messages().clear(storage);
    state::poll_messages().clear(storage);
}

#[cw_serde]
#[deprecated(since = "0.5.0", note = "only used during migration")]
pub struct Config {
    pub governance: Addr,
    pub service_registry_contract: Addr,
    pub service_name: nonempty::String,
    pub source_gateway_address: nonempty::String,
    pub voting_threshold: MajorityThreshold,
    pub block_expiry: u64, // number of blocks after which a poll expires
    pub confirmation_height: u64,
    pub source_chain: ChainName,
    pub rewards_contract: Addr,
    pub msg_id_format: MessageIdFormat,
}
impl From<Config> for Vec<Attribute> {
    fn from(other: Config) -> Self {
        vec![
            ("service_name", other.service_name.to_string()),
            (
                "service_registry_contract",
                other.service_registry_contract.to_string(),
            ),
            (
                "source_gateway_address",
                other.source_gateway_address.to_string(),
            ),
            (
                "voting_threshold",
                serde_json::to_string(&other.voting_threshold)
                    .expect("failed to serialize voting_threshold"),
            ),
            ("block_expiry", other.block_expiry.to_string()),
            ("confirmation_height", other.confirmation_height.to_string()),
        ]
        .into_iter()
        .map(Attribute::from)
        .collect()
    }
}
#[deprecated(since = "0.5.0", note = "only used during migration")]
pub const CONFIG: Item<Config> = Item::new("config");

#[cfg(test)]
mod tests {
    use axelar_wasm_std::msg_id::MessageIdFormat;
    use axelar_wasm_std::permission_control::Permission;
    use axelar_wasm_std::{nonempty, permission_control, MajorityThreshold, Threshold};
    use cosmwasm_schema::cw_serde;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{Addr, Attribute, DepsMut, Empty, Env, Event, MessageInfo, Response};
    use router_api::ChainName;

    use crate::contract::migrations::v0_5_0;
    use crate::contract::{migrate, CONTRACT_NAME, CONTRACT_VERSION};
    use crate::state;

    const GOVERNANCE: &str = "governance";

    #[test]
    fn migrate_checks_contract_version() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());
        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, "something wrong").unwrap();

        assert!(v0_5_0::migrate(deps.as_mut().storage).is_err());

        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, v0_5_0::BASE_VERSION)
            .unwrap();

        assert!(v0_5_0::migrate(deps.as_mut().storage).is_ok());
    }

    #[test]
    fn migrate_sets_contract_version() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());

        migrate(deps.as_mut(), mock_env(), Empty {}).unwrap();

        let contract_version = cw2::get_contract_version(deps.as_mut().storage).unwrap();
        assert_eq!(contract_version.contract, CONTRACT_NAME);
        assert_eq!(contract_version.version, CONTRACT_VERSION);
    }

    #[test]
    fn config_gets_migrated() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());

        assert!(v0_5_0::CONFIG.load(deps.as_mut().storage).is_ok());
        assert!(state::CONFIG.load(deps.as_mut().storage).is_err());

        assert!(v0_5_0::migrate(deps.as_mut().storage).is_ok());

        assert!(v0_5_0::CONFIG.load(deps.as_mut().storage).is_err());
        assert!(state::CONFIG.load(deps.as_mut().storage).is_ok());
    }

    #[test]
    fn permission_control_gets_migrated() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());

        assert!(v0_5_0::migrate(deps.as_mut().storage).is_ok());

        assert!(permission_control::sender_role(
            deps.as_mut().storage,
            &Addr::unchecked(GOVERNANCE)
        )
        .unwrap()
        .contains(Permission::Governance));
    }

    #[test]
    fn state_is_cleared_after_migration() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());

        assert!(v0_5_0::migrate(deps.as_mut().storage).is_ok());

        assert!(state::VOTES.is_empty(deps.as_ref().storage));
        assert!(state::POLLS.is_empty(deps.as_ref().storage));
        assert!(state::poll_messages().is_empty(deps.as_ref().storage));
        assert!(state::poll_verifier_sets().is_empty(deps.as_ref().storage));
    }

    fn instantiate_contract(deps: DepsMut) {
        instantiate(
            deps,
            mock_env(),
            mock_info("admin", &[]),
            InstantiateMsg {
                governance_address: GOVERNANCE.parse().unwrap(),
                service_registry_address: "service_registry".parse().unwrap(),
                service_name: "service".parse().unwrap(),
                source_gateway_address: "source_gateway".parse().unwrap(),
                voting_threshold: Threshold::try_from((2u64, 3u64))
                    .and_then(MajorityThreshold::try_from)
                    .unwrap(),
                block_expiry: 1,
                confirmation_height: 1,
                source_chain: "source-chain".parse().unwrap(),
                rewards_address: "rewards".to_string(),
                msg_id_format: MessageIdFormat::HexTxHashAndEventIndex,
            },
        )
        .unwrap();
    }

    #[deprecated(since = "0.5.0", note = "only used to test the migration")]
    fn instantiate(
        deps: DepsMut,
        _env: Env,
        _info: MessageInfo,
        msg: InstantiateMsg,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        cw2::set_contract_version(deps.storage, CONTRACT_NAME, v0_5_0::BASE_VERSION)?;

        let config = v0_5_0::Config {
            governance: deps.api.addr_validate(&msg.governance_address)?,
            service_name: msg.service_name,
            service_registry_contract: deps.api.addr_validate(&msg.service_registry_address)?,
            source_gateway_address: msg.source_gateway_address,
            voting_threshold: msg.voting_threshold,
            block_expiry: msg.block_expiry,
            confirmation_height: msg.confirmation_height,
            source_chain: msg.source_chain,
            rewards_contract: deps.api.addr_validate(&msg.rewards_address)?,
            msg_id_format: msg.msg_id_format,
        };
        v0_5_0::CONFIG.save(deps.storage, &config)?;

        Ok(Response::new()
            .add_event(Event::new("instantiated").add_attributes(<Vec<Attribute>>::from(config))))
    }

    #[cw_serde]
    #[deprecated(since = "0.5.0", note = "only used to test the migration")]
    pub struct InstantiateMsg {
        /// Address that can call all messages of unrestricted governance permission level, like UpdateVotingThreshold.
        /// It can execute messages that bypasses verification checks to rescue the contract if it got into an otherwise unrecoverable state due to external forces.
        /// On mainnet it should match the address of the Cosmos governance module.
        pub governance_address: nonempty::String,
        /// Service registry contract address on axelar.
        pub service_registry_address: nonempty::String,
        /// Name of service in the service registry for which verifiers are registered.
        pub service_name: nonempty::String,
        /// Axelar's gateway contract address on the source chain
        pub source_gateway_address: nonempty::String,
        /// Threshold of weighted votes required for voting to be considered complete for a particular message
        pub voting_threshold: MajorityThreshold,
        /// The number of blocks after which a poll expires
        pub block_expiry: u64,
        /// The number of blocks to wait for on the source chain before considering a transaction final
        pub confirmation_height: u64,
        /// Name of the source chain
        pub source_chain: ChainName,
        /// Rewards contract address on axelar.
        pub rewards_address: String,
        /// Format that incoming messages should use for the id field of CrossChainId
        pub msg_id_format: MessageIdFormat,
    }
}
