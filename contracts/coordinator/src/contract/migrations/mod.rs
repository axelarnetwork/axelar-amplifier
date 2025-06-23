use std::collections::HashMap;

use axelar_wasm_std::msg_id::MessageIdFormat;
use axelar_wasm_std::{address, migrate_from_version, nonempty, IntoContractError};
use cosmwasm_schema::cw_serde;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Addr, DepsMut, Env, Response};
use cw_storage_plus::{Item, Map};
use error_stack::{report, ResultExt};
use router_api::ChainName;

use crate::contract::errors::Error;
use crate::state;

#[derive(thiserror::Error, Debug, PartialEq, IntoContractError)]
enum MigrationError {
    #[error("cannot have duplicate deployment name '{0}' in migration msg")]
    DuplicateDeployment(String),
    #[error("error deserializing state during migration")]
    Deserialize,
    #[error("missing information for deployment '{0}' from migration")]
    MissingDeploymentFromMsg(String),
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
pub struct ChainContracts {
    pub chain_name: ChainName,
    pub msg_id_format: MessageIdFormat,
    pub gateway: Addr,
    pub voting_verifier: Addr,
    pub multisig_prover: Addr,
}

pub const OLD_DEPLOYED_CHAINS: Map<String, OldChainContracts> = Map::new("deployed_chains");

#[cw_serde]
pub struct ChainNameAndMsgFormat {
    pub deployment_name: nonempty::String,
    pub chain_name: ChainName,
    pub msg_id_format: MessageIdFormat,
}

#[cw_serde]
pub struct MigrateMsg {
    pub router: String,
    pub multisig: String,
    pub chain_contracts: Vec<ChainNameAndMsgFormat>,
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

    let mut new_contract_details: HashMap<String, ChainNameAndMsgFormat> = HashMap::new();
    for contracts in msg.chain_contracts {
        if let Some { .. } =
            new_contract_details.insert(contracts.deployment_name.to_string(), contracts.clone())
        {
            return Err(
                MigrationError::DuplicateDeployment(contracts.deployment_name.to_string()).into(),
            );
        }
    }

    for chain_contracts in OLD_DEPLOYED_CHAINS
        .range(deps.storage, None, None, cosmwasm_std::Order::Ascending)
        .map(|contracts_result| match contracts_result {
            Ok(old_contracts) => Ok(old_contracts.clone()),
            Err(..) => Err(MigrationError::Deserialize.into()),
        })
        .collect::<Result<Vec<_>, axelar_wasm_std::error::ContractError>>()?
    {
        let deployment_details = new_contract_details.get(&chain_contracts.0).ok_or(report!(
            MigrationError::MissingDeploymentFromMsg(chain_contracts.0.clone())
        ))?;

        state::save_deployed_contracts(
            deps.storage,
            axelar_wasm_std::nonempty::String::try_from(chain_contracts.0.clone())
                .change_context(Error::OldConfigNotFound)?,
            state::ChainContracts {
                chain_name: deployment_details.chain_name.clone(),
                msg_id_format: deployment_details.msg_id_format.clone(),
                gateway: chain_contracts.1.gateway,
                voting_verifier: chain_contracts.1.voting_verifier,
                multisig_prover: chain_contracts.1.multisig_prover,
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
    use router_api::ChainName;

    use crate::contract::errors::Error;
    use crate::contract::migrations::{
        ChainNameAndMsgFormat, OldChainContracts, OldConfig, OLD_CONFIG, OLD_DEPLOYED_CHAINS,
    };
    use crate::contract::{migrate, MigrateMsg};
    use crate::state;
    use crate::state::ProtocolContracts;

    const OLD_CONTRACT_NAME: &str = "coordinator";
    const OLD_CONTRACT_VERSION: &str = "1.1.0";

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
                chain_contracts: vec![ChainNameAndMsgFormat {
                    deployment_name: nonempty_str!("deployment"),
                    chain_name: chain_name.clone(),
                    msg_id_format: MessageIdFormat::FieldElementAndEventIndex,
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
}
