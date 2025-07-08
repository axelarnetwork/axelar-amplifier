use std::collections::HashMap;

use axelar_wasm_std::{address, migrate_from_version, IntoContractError};
use cosmwasm_schema::cw_serde;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Addr, DepsMut, Env, Order, Response, Storage};
use cw_storage_plus::{index_list, IndexedMap, Item, UniqueIndex};
use error_stack::{ensure, report, ResultExt};
use itertools::Itertools;
use router_api::ChainName;

use crate::contract::errors::Error;
use crate::state;

#[derive(thiserror::Error, Debug, PartialEq, IntoContractError)]
enum MigrationError {
    #[error("missing contracts to register for chain {0}")]
    MissingContracts(ChainName),
    #[error("expected prover address {0} but saw {1}")]
    IncorrectProver(Addr, Addr),
    #[error("chain {0} not found in contract state")]
    ExtraProver(ChainName),
    #[error("chain contracts provided for chain {0} do not match with current state")]
    IncorrectContracts(ChainName),
}

#[cw_serde]
pub struct OldConfig {
    pub service_registry: Addr,
}

pub const OLD_CONFIG: Item<OldConfig> = Item::new("config");

type ProverAddress = Addr;
// Legacy prover storage - maintained for backward compatibility
#[index_list(ProverAddress)]
struct ChainProverIndexes<'a> {
    pub by_prover: UniqueIndex<'a, ProverAddress, ProverAddress, ChainName>,
}

const OLD_CHAIN_PROVER_INDEXED_MAP: IndexedMap<ChainName, ProverAddress, ChainProverIndexes> =
    IndexedMap::new(
        "chain_prover_map",
        ChainProverIndexes {
            by_prover: UniqueIndex::new(|prover| prover.clone(), "chain_prover_map_by_prover"),
        },
    );

#[cw_serde]
pub struct OldChainContracts {
    pub gateway: Addr,
    pub voting_verifier: Addr,
    pub multisig_prover: Addr,
}

#[cw_serde]
pub struct MigrateMsg {
    pub router: String,
    pub multisig: String,
    pub chain_contracts: Vec<state::ChainContractsRecord>,
}

#[cfg_attr(not(feature = "library"), entry_point)]
#[migrate_from_version("1.1")]
pub fn migrate(
    mut deps: DepsMut,
    _env: Env,
    msg: MigrateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    migrate_config(&mut deps, &msg)?;

    // Since this state has not yet been set or used, we can just clear it
    state::DEPLOYED_CHAINS.clear(deps.storage);

    migrate_chain_contracts(deps.storage, msg.chain_contracts)?;

    Ok(Response::default())
}

fn migrate_config(
    deps: &mut DepsMut,
    msg: &MigrateMsg,
) -> Result<(), axelar_wasm_std::error::ContractError> {
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
    Ok(())
}

fn migrate_chain_contracts(
    storage: &mut dyn Storage,
    chain_contracts: Vec<state::ChainContractsRecord>,
) -> Result<(), axelar_wasm_std::error::ContractError> {
    let provers_by_chain: Vec<_> = OLD_CHAIN_PROVER_INDEXED_MAP
        .range(storage, None, None, Order::Ascending)
        .try_collect()?;

    let mut contracts_by_chain: HashMap<_, _> = chain_contracts
        .into_iter()
        .map(|contracts| (contracts.chain_name.clone(), contracts))
        .collect();

    for (chain_name, prover_addr) in provers_by_chain {
        let contracts = contracts_by_chain
            .remove(&chain_name)
            .ok_or_else(|| MigrationError::MissingContracts(chain_name.clone()))?;

        if contracts.prover_address != prover_addr {
            Err(MigrationError::IncorrectProver(
                prover_addr,
                contracts.prover_address.clone(),
            ))?;
        }

        match state::contracts_by_chain(storage, contracts.chain_name.clone()) {
            Ok(existing_contracts) if existing_contracts != contracts => {
                Err(MigrationError::IncorrectContracts(contracts.chain_name))?;
            }
            _ => {
                state::save_chain_contracts(
                    storage,
                    contracts.chain_name,
                    contracts.prover_address,
                    contracts.gateway_address,
                    contracts.verifier_address,
                )?;
            }
        }
    }

    if let Some(extra_chain) = contracts_by_chain.keys().next() {
        Err(MigrationError::ExtraProver(extra_chain.clone()))?;
    }

    Ok(())
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
        ChainContractsDetails, MigrationError, OldChainContracts, OldConfig, ProverAddress,
        OLD_CONFIG,
    };
    use crate::contract::{migrate, MigrateMsg};
    use crate::state;
    use crate::state::ProtocolContracts;

    const OLD_CONTRACT_NAME: &str = "coordinator";
    const OLD_CONTRACT_VERSION: &str = "1.1.0";

    pub const OLD_DEPLOYED_CHAINS: Map<String, OldChainContracts> = Map::new("deployed_chains");
    use super::OLD_CHAIN_PROVER_INDEXED_MAP;

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

    fn add_old_prover_registration(
        deps: DepsMut,
        provers: Vec<(ChainName, ProverAddress)>,
    ) -> Result<(), Error> {
        for (chain_name, prover_addr) in provers {
            OLD_CHAIN_PROVER_INDEXED_MAP
                .save(deps.storage, chain_name, &prover_addr)
                .map_err(|_| Error::UnableToPersistProtocol)?;
        }

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
                chain_deployments: vec![ChainContractsDetails {
                    gateway: gateway.clone(),
                    deployment_name: nonempty_str!("deployment"),
                    chain_name: chain_name.clone(),
                    msg_id_format: MessageIdFormat::FieldElementAndEventIndex,
                    voting_verifier: voting_verifier.clone(),
                    multisig_prover: multisig_prover.clone(),
                },],
                chain_contracts: vec![],
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
                chain_deployments: vec![
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
                        chain_name,
                        msg_id_format: MessageIdFormat::HexTxHash,
                        voting_verifier,
                        multisig_prover,
                    },
                ],
                chain_contracts: vec![],
            },
        );

        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains(
            &MigrationError::DuplicateDeployment(nonempty_str!("deployment")).to_string()
        ));
    }

    #[test]
    fn migrate_properly_registers_provers() {
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

        // Register old provers using the helper function
        let chain_name = ChainName::try_from("axelar").unwrap();
        let prover_addr = api.addr_make("prover");
        let gateway_addr = api.addr_make("gateway");
        let verifier_addr = api.addr_make("verifier");

        assert!(add_old_prover_registration(
            deps.as_mut(),
            vec![(chain_name.clone(), prover_addr.clone())]
        )
        .is_ok());

        // Verify the old prover is registered
        let old_prover_registration =
            OLD_CHAIN_PROVER_INDEXED_MAP.load(&deps.storage, chain_name.clone());
        assert!(old_prover_registration.is_ok());
        let old_prover_registration = old_prover_registration.unwrap();
        assert_eq!(old_prover_registration, prover_addr);

        let router = api.addr_make("router");
        let multisig = api.addr_make("multisig");

        // Create migration message with matching chain contracts
        let res = migrate(
            deps.as_mut(),
            env,
            MigrateMsg {
                router: router.to_string(),
                multisig: multisig.to_string(),
                chain_deployments: vec![],
                chain_contracts: vec![state::ChainContractsRecord {
                    chain_name: chain_name.clone(),
                    prover_address: prover_addr.clone(),
                    gateway_address: gateway_addr.clone(),
                    verifier_address: verifier_addr.clone(),
                }],
            },
        );

        assert!(res.is_ok());

        // Verify the prover is now registered in the new state
        let contracts = state::contracts_by_chain(&deps.storage, chain_name.clone());
        assert!(contracts.is_ok());
        let contracts = contracts.unwrap();

        assert_eq!(contracts.chain_name, chain_name);
        assert_eq!(contracts.prover_address, prover_addr);
        assert_eq!(contracts.gateway_address, gateway_addr);
        assert_eq!(contracts.verifier_address, verifier_addr);

        // Verify we can also look up by prover address
        let contracts_by_prover = state::contracts_by_prover(&deps.storage, prover_addr.clone());
        assert!(contracts_by_prover.is_ok());
        let contracts_by_prover = contracts_by_prover.unwrap();
        assert_eq!(contracts_by_prover.chain_name, chain_name);
    }

    #[test]
    fn migrate_fails_with_incorrect_prover_address() {
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

        // Register old provers using the helper function
        let chain_name = ChainName::try_from("axelar").unwrap();
        let prover_addr1 = api.addr_make("prover1");
        let prover_addr2 = api.addr_make("prover2");
        let gateway_addr = api.addr_make("gateway");
        let verifier_addr = api.addr_make("verifier");

        assert!(add_old_prover_registration(
            deps.as_mut(),
            vec![(chain_name.clone(), prover_addr2.clone())]
        )
        .is_ok());

        let router = api.addr_make("router");
        let multisig = api.addr_make("multisig");

        // Create migration message with matching chain contracts
        let res = migrate(
            deps.as_mut(),
            env,
            MigrateMsg {
                router: router.to_string(),
                multisig: multisig.to_string(),
                chain_deployments: vec![],
                chain_contracts: vec![state::ChainContractsRecord {
                    chain_name: chain_name.clone(),
                    prover_address: prover_addr1.clone(),
                    gateway_address: gateway_addr.clone(),
                    verifier_address: verifier_addr.clone(),
                }],
            },
        );

        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains(&MigrationError::IncorrectProver(prover_addr2, prover_addr1).to_string()));
    }

    #[test]
    fn migrate_fails_to_migrate_all_registered_provers() {
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

        // Register old provers using the helper function
        let chain_name1 = ChainName::try_from("axelar").unwrap();
        let chain_name2 = ChainName::try_from("cosmos").unwrap();
        let prover_addr1 = api.addr_make("prover1");
        let prover_addr2 = api.addr_make("prover2");
        let gateway_addr = api.addr_make("gateway");
        let verifier_addr = api.addr_make("verifier");

        assert!(add_old_prover_registration(
            deps.as_mut(),
            vec![
                (chain_name1.clone(), prover_addr1.clone()),
                (chain_name2.clone(), prover_addr2.clone())
            ]
        )
        .is_ok());

        let router = api.addr_make("router");
        let multisig = api.addr_make("multisig");

        // Create migration message with matching chain contracts
        let res = migrate(
            deps.as_mut(),
            env,
            MigrateMsg {
                router: router.to_string(),
                multisig: multisig.to_string(),
                chain_deployments: vec![],
                chain_contracts: vec![state::ChainContractsRecord {
                    chain_name: chain_name1.clone(),
                    prover_address: prover_addr1.clone(),
                    gateway_address: gateway_addr.clone(),
                    verifier_address: verifier_addr.clone(),
                }],
            },
        );

        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains(&MigrationError::MissingContracts(chain_name2).to_string()));
    }

    #[test]
    fn migrate_fails_with_extra_prover_in_migration_msg() {
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

        // Register old provers using the helper function
        let chain_name = ChainName::try_from("axelar").unwrap();
        let prover_addr = api.addr_make("prover");
        let gateway_addr = api.addr_make("gateway");
        let verifier_addr = api.addr_make("verifier");

        // Only register one chain in the old state
        assert!(add_old_prover_registration(
            deps.as_mut(),
            vec![(chain_name.clone(), prover_addr.clone())]
        )
        .is_ok());

        let router = api.addr_make("router");
        let multisig = api.addr_make("multisig");

        // Create migration message with an extra chain that wasn't registered
        let extra_chain_name = ChainName::try_from("cosmos").unwrap();
        let res = migrate(
            deps.as_mut(),
            env,
            MigrateMsg {
                router: router.to_string(),
                multisig: multisig.to_string(),
                chain_deployments: vec![],
                chain_contracts: vec![
                    state::ChainContractsRecord {
                        chain_name: chain_name.clone(),
                        prover_address: prover_addr.clone(),
                        gateway_address: gateway_addr.clone(),
                        verifier_address: verifier_addr.clone(),
                    },
                    state::ChainContractsRecord {
                        chain_name: extra_chain_name.clone(),
                        prover_address: api.addr_make("extra_prover"),
                        gateway_address: api.addr_make("extra_gateway"),
                        verifier_address: api.addr_make("extra_verifier"),
                    },
                ],
            },
        );

        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains(&MigrationError::ExtraProver(extra_chain_name).to_string()));
    }

    #[test]
    fn migrate_fails_with_incorrect_contracts_in_migration_msg() {
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

        // Register old provers using the helper function
        let chain_name = ChainName::try_from("axelar").unwrap();
        let prover_addr = api.addr_make("prover");
        let gateway_addr = api.addr_make("gateway");
        let verifier_addr = api.addr_make("verifier");

        assert!(add_old_prover_registration(
            deps.as_mut(),
            vec![(chain_name.clone(), prover_addr.clone())]
        )
        .is_ok());

        // Save chain contracts in the new state (simulating previous registration)
        state::save_chain_contracts(
            deps.as_mut().storage,
            chain_name.clone(),
            prover_addr.clone(),
            gateway_addr.clone(),
            verifier_addr.clone(),
        )
        .unwrap();

        let router = api.addr_make("router");
        let multisig = api.addr_make("multisig");

        // Create migration message with different contract addresses
        let res = migrate(
            deps.as_mut(),
            env,
            MigrateMsg {
                router: router.to_string(),
                multisig: multisig.to_string(),
                chain_deployments: vec![],
                chain_contracts: vec![state::ChainContractsRecord {
                    chain_name: chain_name.clone(),
                    prover_address: prover_addr.clone(),
                    gateway_address: api.addr_make("different_gateway"), // Different gateway
                    verifier_address: verifier_addr.clone(),
                }],
            },
        );

        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains(&MigrationError::IncorrectContracts(chain_name).to_string()));
    }

    #[test]
    fn migrate_succeeds_with_matching_contracts_in_state() {
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

        // Register old provers using the helper function
        let chain_name = ChainName::try_from("axelar").unwrap();
        let prover_addr = api.addr_make("prover");
        let gateway_addr = api.addr_make("gateway");
        let verifier_addr = api.addr_make("verifier");

        assert!(add_old_prover_registration(
            deps.as_mut(),
            vec![(chain_name.clone(), prover_addr.clone())]
        )
        .is_ok());

        // Save chain contracts in the new state (simulating previous registration)
        state::save_chain_contracts(
            deps.as_mut().storage,
            chain_name.clone(),
            prover_addr.clone(),
            gateway_addr.clone(),
            verifier_addr.clone(),
        )
        .unwrap();

        let router = api.addr_make("router");
        let multisig = api.addr_make("multisig");

        // Create migration message with matching contract addresses
        let res = migrate(
            deps.as_mut(),
            env,
            MigrateMsg {
                router: router.to_string(),
                multisig: multisig.to_string(),
                chain_deployments: vec![],
                chain_contracts: vec![state::ChainContractsRecord {
                    chain_name: chain_name.clone(),
                    prover_address: prover_addr.clone(),
                    gateway_address: gateway_addr.clone(),
                    verifier_address: verifier_addr.clone(),
                }],
            },
        );

        assert!(res.is_ok());

        // Verify the contracts are still correctly stored after migration
        let contracts = state::contracts_by_chain(&deps.storage, chain_name.clone());
        assert!(contracts.is_ok());
        let contracts = contracts.unwrap();

        assert_eq!(contracts.chain_name, chain_name);
        assert_eq!(contracts.prover_address, prover_addr);
        assert_eq!(contracts.gateway_address, gateway_addr);
        assert_eq!(contracts.verifier_address, verifier_addr);

        // Verify we can also look up by prover address
        let contracts_by_prover = state::contracts_by_prover(&deps.storage, prover_addr.clone());
        assert!(contracts_by_prover.is_ok());
        let contracts_by_prover = contracts_by_prover.unwrap();
        assert_eq!(contracts_by_prover.chain_name, chain_name);
    }
}
