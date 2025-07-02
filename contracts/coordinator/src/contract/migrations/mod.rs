use std::collections::HashMap;

use axelar_wasm_std::msg_id::MessageIdFormat;
use axelar_wasm_std::{address, migrate_from_version, nonempty, IntoContractError};
use cosmwasm_schema::cw_serde;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Addr, DepsMut, Env, Response};
use cw_storage_plus::Item;
use error_stack::{report, ResultExt};
use router_api::ChainName;

use crate::contract::errors::Error;
use crate::state;

#[derive(thiserror::Error, Debug, PartialEq, IntoContractError)]
enum MigrationError {
    #[error("cannot have duplicate deployment name '{0}' in migration msg")]
    DuplicateDeployment(nonempty::String),
}

#[cw_serde]
pub struct OldConfig {
    pub service_registry: Addr,
}

pub const OLD_CONFIG: Item<OldConfig> = Item::new("config");

#[cw_serde]
pub struct OldChainContracts {
    pub gateway: Addr,
    pub voting_verifier: Addr,
    pub multisig_prover: Addr,
}

#[cw_serde]
#[derive(Eq, Hash)]
pub struct ChainContractsDetails {
    pub deployment_name: nonempty::String,
    pub chain_name: ChainName,
    pub msg_id_format: MessageIdFormat,
    pub gateway: Addr,
    pub voting_verifier: Addr,
    pub multisig_prover: Addr,
}

#[cw_serde]
pub struct MigrateMsg {
    pub router: String,
    pub multisig: String,
    pub chain_contracts: Vec<ChainContractsDetails>,
}

#[cfg_attr(not(feature = "library"), entry_point)]
#[migrate_from_version("1.1")]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    msg: MigrateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    let old_config = OLD_CONFIG
        .load(deps.storage)
        .change_context(Error::OldConfigNotFound)?;

    let router = address::validate_cosmwasm_address(deps.api, &msg.router)?;
    let multisig = address::validate_cosmwasm_address(deps.api, &msg.multisig)?;

    OLD_CONFIG.remove(deps.storage);

    let protocol = &state::ProtocolContracts {
        service_registry: old_config.service_registry,
        router,
        multisig,
    };

    state::save_protocol_contracts(deps.storage, protocol)
        .change_context(Error::UnableToPersistProtocol)?;

    let mut chain_contracts: HashMap<nonempty::String, ChainContractsDetails> = HashMap::new();

    for cc in msg.chain_contracts {
        if chain_contracts
            .insert(cc.deployment_name.clone(), cc.clone())
            .is_some()
        {
            return Err(MigrationError::DuplicateDeployment(cc.deployment_name.clone()).into());
        }
    }

    // Since this state has not yet been set or used, we can clear
    // it and repopulate it.
    state::DEPLOYED_CHAINS.clear(deps.storage);

    for (deployement, contracts) in chain_contracts {
        state::save_deployed_contracts(
            deps.storage,
            deployement,
            state::ChainContracts {
                chain_name: contracts.chain_name.clone(),
                msg_id_format: contracts.msg_id_format.clone(),
                gateway: contracts.gateway,
                voting_verifier: contracts.voting_verifier,
                multisig_prover: contracts.multisig_prover,
            },
        )?;
    }

    Ok(Response::default())
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::error::ContractError;
    use axelar_wasm_std::msg_id::MessageIdFormat;
    use axelar_wasm_std::{address, nonempty, nonempty_str, permission_control};
    use cosmwasm_schema::cw_serde;
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};
    use cw_storage_plus::Map;
    use router_api::ChainName;

    use crate::contract::errors::Error;
    use crate::contract::migrations::{
        ChainContractsDetails, MigrationError, OldChainContracts, OldConfig, OLD_CONFIG,
    };
    use crate::contract::{migrate, MigrateMsg};
    use crate::state;
    use crate::state::ProtocolContracts;

    const OLD_CONTRACT_NAME: &str = "coordinator";
    const OLD_CONTRACT_VERSION: &str = "1.1.0";

    pub const OLD_DEPLOYED_CHAINS: Map<String, OldChainContracts> = Map::new("deployed_chains");

    #[cw_serde]
    pub struct OldInstantiateMsg {
        pub governance_address: String,
        pub service_registry: String,
    }

    fn old_instantiate(
        deps: DepsMut,
        _env: Env,
        _info: MessageInfo,
        msg: OldInstantiateMsg,
    ) -> Result<Response, ContractError> {
        cw2::set_contract_version(deps.storage, OLD_CONTRACT_NAME, OLD_CONTRACT_VERSION)?;

        let config = OldConfig {
            service_registry: address::validate_cosmwasm_address(deps.api, &msg.service_registry)?,
        };
        OLD_CONFIG.save(deps.storage, &config)?;

        let governance = address::validate_cosmwasm_address(deps.api, &msg.governance_address)?;
        permission_control::set_governance(deps.storage, &governance)?;

        Ok(Response::default())
    }

    fn add_old_deployment(
        deps: DepsMut,
        deployment_name: nonempty::String,
        old_contracts: OldChainContracts,
    ) -> Result<(), Error> {
        OLD_DEPLOYED_CHAINS
            .save(deps.storage, deployment_name.to_string(), &old_contracts)
            .map_err(|_| Error::UnableToPersistProtocol)?;

        Ok(())
    }

    #[test]
    fn migrate_sets_contract_addresses_correctly() {
        let mut deps = mock_dependencies();
        let api = deps.api;
        let env = mock_env();
        let info = message_info(&api.addr_make("sender"), &[]);

        let service_registry = api.addr_make("service_registry");
        old_instantiate(
            deps.as_mut(),
            env.clone(),
            info,
            OldInstantiateMsg {
                governance_address: api.addr_make("governance").to_string(),
                service_registry: service_registry.to_string(),
            },
        )
        .unwrap();

        let gateway = api.addr_make("gateway");
        let voting_verifier = api.addr_make("verifier");
        let multisig_prover = api.addr_make("prover");
        let chain_name = ChainName::try_from("axelar");

        assert!(chain_name.is_ok());
        let chain_name = chain_name.unwrap();

        assert!(add_old_deployment(
            deps.as_mut(),
            nonempty_str!("deployment"),
            OldChainContracts {
                gateway: gateway.clone(),
                voting_verifier: voting_verifier.clone(),
                multisig_prover: multisig_prover.clone(),
            }
        )
        .is_ok());

        let router = api.addr_make("router");
        let multisig = api.addr_make("multisig");
        assert!(migrate(
            deps.as_mut(),
            env,
            MigrateMsg {
                router: router.to_string(),
                multisig: multisig.to_string(),
                chain_contracts: vec![ChainContractsDetails {
                    gateway: gateway.clone(),
                    deployment_name: nonempty_str!("deployment"),
                    chain_name: chain_name.clone(),
                    msg_id_format: MessageIdFormat::FieldElementAndEventIndex,
                    voting_verifier: voting_verifier.clone(),
                    multisig_prover: multisig_prover.clone(),
                },],
            },
        )
        .is_ok());

        assert!(!OLD_CONFIG.exists(&deps.storage));

        assert_eq!(
            state::protocol_contracts(&deps.storage).ok(),
            Some(ProtocolContracts {
                service_registry,
                router,
                multisig,
            })
        );

        assert!(OLD_DEPLOYED_CHAINS.has(&deps.storage, "deployment".to_string()));

        let deployment = state::deployed_contracts(&deps.storage, nonempty_str!("deployment"));
        assert!(deployment.is_ok());
        let deployment = deployment.unwrap();

        assert_eq!(
            deployment,
            state::ChainContracts {
                chain_name: chain_name.clone(),
                msg_id_format: MessageIdFormat::FieldElementAndEventIndex,
                gateway,
                voting_verifier,
                multisig_prover,
            }
        )
    }

    #[test]
    fn migrate_fails_with_duplicate_deployment_ids_in_migration_msg() {
        let mut deps = mock_dependencies();
        let api = deps.api;
        let env = mock_env();
        let info = message_info(&api.addr_make("sender"), &[]);

        let service_registry = api.addr_make("service_registry");
        old_instantiate(
            deps.as_mut(),
            env.clone(),
            info,
            OldInstantiateMsg {
                governance_address: api.addr_make("governance").to_string(),
                service_registry: service_registry.to_string(),
            },
        )
        .unwrap();

        let gateway = api.addr_make("gateway");
        let voting_verifier = api.addr_make("verifier");
        let multisig_prover = api.addr_make("prover");

        assert!(add_old_deployment(
            deps.as_mut(),
            nonempty_str!("deployment"),
            OldChainContracts {
                gateway: gateway.clone(),
                voting_verifier: voting_verifier.clone(),
                multisig_prover: multisig_prover.clone(),
            }
        )
        .is_ok());

        let router = api.addr_make("router");
        let multisig = api.addr_make("multisig");
        let chain_name = ChainName::try_from("axelar").unwrap();

        let res = migrate(
            deps.as_mut(),
            env,
            MigrateMsg {
                router: router.to_string(),
                multisig: multisig.to_string(),
                chain_contracts: vec![
                    ChainContractsDetails {
                        gateway: gateway.clone(),
                        deployment_name: nonempty_str!("deployment"),
                        chain_name: chain_name.clone(),
                        msg_id_format: MessageIdFormat::FieldElementAndEventIndex,
                        voting_verifier: voting_verifier.clone(),
                        multisig_prover: multisig_prover.clone(),
                    },
                    ChainContractsDetails {
                        gateway,
                        deployment_name: nonempty_str!("deployment"),
                        chain_name: chain_name.clone(),
                        msg_id_format: MessageIdFormat::HexTxHash,
                        voting_verifier,
                        multisig_prover,
                    },
                ],
            },
        );

        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains(
            &MigrationError::DuplicateDeployment(nonempty_str!("deployment")).to_string()
        ));
    }
}
