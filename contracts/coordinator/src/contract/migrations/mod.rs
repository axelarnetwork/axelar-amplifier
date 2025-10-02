use std::collections::{HashMap, HashSet};

use axelar_wasm_std::{address, migrate_from_version, nonempty, IntoContractError};
use cosmwasm_schema::cw_serde;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Addr, DepsMut, Env, Order, Response, Storage};
use cw_storage_plus::{index_list, IndexedMap, Item, UniqueIndex};
use error_stack::{report, ResultExt};
use itertools::Itertools;
use router_api::ChainName;

use crate::contract::errors::Error;
use crate::state::{
    contracts_by_chain, save_chain_contracts, save_protocol_contracts, ChainContractsRecord,
    ProtocolContracts, DEPLOYED_CHAINS,
};

#[derive(thiserror::Error, Debug, PartialEq, IntoContractError)]
enum MigrationError {
    #[error("contract config before migration not found")]
    OldConfigNotFound,
    #[error("extra or duplicate chains provided in message")]
    ExtraChainProvided,
    #[error("chain contracts provided for chain {0} do not match with current state")]
    IncorrectContracts(ChainName),
    #[error("error parsing chain contracts")]
    InvalidChainContracts,
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
pub struct ChainContracts {
    pub chain_name: ChainName,
    pub prover_address: Option<nonempty::String>,
    pub gateway_address: nonempty::String,
    pub verifier_address: nonempty::String,
}

#[cw_serde]
pub struct MigrateMsg {
    pub router: String,
    pub multisig: String,
    pub chain_contracts: Vec<ChainContracts>,
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
    DEPLOYED_CHAINS.clear(deps.storage);

    migrate_chain_contracts(deps, msg.chain_contracts)?;

    Ok(Response::default())
}

fn migrate_config(
    deps: &mut DepsMut,
    msg: &MigrateMsg,
) -> Result<(), axelar_wasm_std::error::ContractError> {
    let old_config = OLD_CONFIG
        .load(deps.storage)
        .change_context(MigrationError::OldConfigNotFound)?;

    OLD_CONFIG.remove(deps.storage);

    let protocol = &ProtocolContracts {
        service_registry: old_config.service_registry,
        router: address::validate_cosmwasm_address(deps.api, &msg.router)?,
        multisig: address::validate_cosmwasm_address(deps.api, &msg.multisig)?,
    };

    Ok(save_protocol_contracts(deps.storage, protocol)
        .change_context(Error::UnableToPersistProtocol)?)
}

fn migrate_chain_contracts(
    mut deps: DepsMut,
    chain_contracts: Vec<ChainContracts>,
) -> Result<(), axelar_wasm_std::error::ContractError> {
    let provers_by_chain: HashMap<_, _> = OLD_CHAIN_PROVER_INDEXED_MAP
        .range(deps.storage, None, None, Order::Ascending)
        .try_collect()?;

    let mut chain_names_seen: HashSet<ChainName> = HashSet::new();
    let mut contracts_map: HashMap<_, _> = chain_contracts
        .into_iter()
        .map(|contracts| {
            if !chain_names_seen.insert(contracts.chain_name.clone()) {
                Err(MigrationError::ExtraChainProvided)
            } else {
                Ok((contracts.chain_name.clone(), contracts))
            }
        })
        .collect::<Result<HashMap<ChainName, ChainContracts>, MigrationError>>()?;

    migrate_all_provers(&mut deps, provers_by_chain, &mut contracts_map)
}

fn migrate_all_provers(
    deps: &mut DepsMut,
    provers_by_chain: HashMap<ChainName, Addr>,
    contracts_map: &mut HashMap<ChainName, ChainContracts>,
) -> Result<(), axelar_wasm_std::error::ContractError> {
    for contracts in contracts_map.values() {
        let prover_address = contracts
            .prover_address
            .as_ref()
            .map(|addr| {
                address::validate_cosmwasm_address(deps.api, addr)
                    .change_context(MigrationError::InvalidChainContracts)
            })
            .transpose()?
            .or_else(|| provers_by_chain.get(&contracts.chain_name).cloned());

        if let Some(pa) = prover_address {
            save_contracts_to_state(
                deps.storage,
                ChainContractsRecord {
                    chain_name: contracts.chain_name.clone(),
                    prover_address: pa,
                    verifier_address: address::validate_cosmwasm_address(
                        deps.api,
                        &contracts.verifier_address,
                    )
                    .change_context(MigrationError::InvalidChainContracts)?,
                    gateway_address: address::validate_cosmwasm_address(
                        deps.api,
                        &contracts.gateway_address,
                    )
                    .change_context(MigrationError::InvalidChainContracts)?,
                },
            )?;
        }
    }

    Ok(())
}

fn save_contracts_to_state(
    storage: &mut dyn Storage,
    contracts: ChainContractsRecord,
) -> Result<(), axelar_wasm_std::error::ContractError> {
    match contracts_by_chain(storage, contracts.chain_name.clone()) {
        Ok(existing_contracts) if existing_contracts != contracts => {
            Err(MigrationError::IncorrectContracts(contracts.chain_name).into())
        }
        _ => Ok(save_chain_contracts(
            storage,
            contracts.chain_name,
            contracts.prover_address,
            contracts.gateway_address,
            contracts.verifier_address,
        )?),
    }
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::error::ContractError;
    use axelar_wasm_std::{address, nonempty, permission_control};
    use cosmwasm_schema::cw_serde;
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};
    use router_api::{chain_name, cosmos_addr, ChainName};

    use crate::contract::errors::Error;
    use crate::contract::migrations::{MigrationError, OldConfig, ProverAddress, OLD_CONFIG};
    use crate::contract::{migrate, MigrateMsg};
    use crate::state;

    const OLD_CONTRACT_NAME: &str = "coordinator";
    const OLD_CONTRACT_VERSION: &str = "1.1.0";

    use super::{ChainContracts, OLD_CHAIN_PROVER_INDEXED_MAP};

    const PROVER_1: &str = "prover";
    const PROVER_2: &str = "prover2";
    const GATEWAY_1: &str = "gateway1";
    const VERIFIER_1: &str = "verifier1";
    const GATEWAY_2: &str = "gateway2";
    const VERIFIER_2: &str = "verifier2";
    const CHAIN_1: &str = "axelar";
    const CHAIN_2: &str = "cosmos";

    const MULTISIG: &str = "multisig";
    const ROUTER: &str = "router";
    const SERVICE_REGISTRY: &str = "service_registry";
    const GOVERNANCE: &str = "governance";

    const SENDER: &str = "sender";

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
    fn migrate_properly_registers_provers() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = message_info(&cosmos_addr!(SENDER), &[]);

        assert!(old_instantiate(
            deps.as_mut(),
            env.clone(),
            info,
            OldInstantiateMsg {
                governance_address: cosmos_addr!(GOVERNANCE).to_string(),
                service_registry: cosmos_addr!(SERVICE_REGISTRY).to_string(),
            },
        )
        .is_ok());

        let chain_name = chain_name!(CHAIN_1);
        let prover_addr = cosmos_addr!(PROVER_1);
        let gateway_addr = cosmos_addr!(GATEWAY_1);
        let verifier_addr = cosmos_addr!(VERIFIER_1);

        assert!(add_old_prover_registration(
            deps.as_mut(),
            vec![(chain_name.clone(), prover_addr.clone())]
        )
        .is_ok());

        let old_prover_registration =
            OLD_CHAIN_PROVER_INDEXED_MAP.load(&deps.storage, chain_name.clone());
        assert!(old_prover_registration.is_ok());
        assert_eq!(old_prover_registration.unwrap(), prover_addr);

        assert!(migrate(
            deps.as_mut(),
            env,
            MigrateMsg {
                router: cosmos_addr!(ROUTER).to_string(),
                multisig: cosmos_addr!(MULTISIG).to_string(),
                chain_contracts: vec![ChainContracts {
                    chain_name: chain_name.clone(),
                    prover_address: None,
                    gateway_address: nonempty::String::try_from(gateway_addr.to_string()).unwrap(),
                    verifier_address: nonempty::String::try_from(verifier_addr.to_string())
                        .unwrap(),
                }],
            },
        )
        .is_ok());

        let contracts = state::contracts_by_chain(&deps.storage, chain_name.clone());
        assert!(contracts.is_ok());
        let contracts = contracts.unwrap();

        assert_eq!(contracts.chain_name, chain_name);
        assert_eq!(contracts.prover_address, prover_addr);
        assert_eq!(contracts.gateway_address, gateway_addr);
        assert_eq!(contracts.verifier_address, verifier_addr);

        let contracts_by_prover = state::contracts_by_prover(&deps.storage, prover_addr.clone());
        assert!(contracts_by_prover.is_ok());
        assert_eq!(contracts_by_prover.unwrap().chain_name, chain_name);
    }

    #[test]
    fn migrate_fails_to_migrate_all_registered_provers() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = message_info(&cosmos_addr!(SENDER), &[]);

        assert!(old_instantiate(
            deps.as_mut(),
            env.clone(),
            info,
            OldInstantiateMsg {
                governance_address: cosmos_addr!(GOVERNANCE).to_string(),
                service_registry: cosmos_addr!(SERVICE_REGISTRY).to_string(),
            },
        )
        .is_ok());

        let chain_name1 = chain_name!(CHAIN_1);
        let chain_name2 = chain_name!(CHAIN_2);
        let prover_addr1 = cosmos_addr!(PROVER_1);
        let prover_addr2 = cosmos_addr!(PROVER_2);
        let gateway_addr = cosmos_addr!(GATEWAY_1);
        let verifier_addr = cosmos_addr!(VERIFIER_1);

        assert!(add_old_prover_registration(
            deps.as_mut(),
            vec![
                (chain_name1.clone(), prover_addr1.clone()),
                (chain_name2.clone(), prover_addr2.clone())
            ]
        )
        .is_ok());

        let res = migrate(
            deps.as_mut(),
            env,
            MigrateMsg {
                router: cosmos_addr!(ROUTER).to_string(),
                multisig: cosmos_addr!(MULTISIG).to_string(),
                chain_contracts: vec![
                    ChainContracts {
                        chain_name: chain_name1.clone(),
                        prover_address: None,
                        gateway_address: nonempty::String::try_from(gateway_addr.to_string())
                            .unwrap(),
                        verifier_address: nonempty::String::try_from(verifier_addr.to_string())
                            .unwrap(),
                    },
                    ChainContracts {
                        chain_name: chain_name1.clone(),
                        prover_address: None,
                        gateway_address: nonempty::String::try_from(gateway_addr.to_string())
                            .unwrap(),
                        verifier_address: nonempty::String::try_from(verifier_addr.to_string())
                            .unwrap(),
                    },
                ],
            },
        );

        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains(&MigrationError::ExtraChainProvided.to_string()));
    }

    #[test]
    fn migrate_fails_with_incorrect_contracts_in_migration_msg() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = message_info(&cosmos_addr!(SENDER), &[]);

        assert!(old_instantiate(
            deps.as_mut(),
            env.clone(),
            info,
            OldInstantiateMsg {
                governance_address: cosmos_addr!(GOVERNANCE).to_string(),
                service_registry: cosmos_addr!(SERVICE_REGISTRY).to_string(),
            },
        )
        .is_ok());

        let chain_name = chain_name!(CHAIN_1);
        let prover_addr = cosmos_addr!(PROVER_1);
        let gateway_addr = cosmos_addr!(GATEWAY_1);
        let verifier_addr = cosmos_addr!(VERIFIER_1);

        assert!(add_old_prover_registration(
            deps.as_mut(),
            vec![(chain_name.clone(), prover_addr.clone())]
        )
        .is_ok());

        state::save_chain_contracts(
            deps.as_mut().storage,
            chain_name.clone(),
            prover_addr.clone(),
            gateway_addr.clone(),
            verifier_addr.clone(),
        )
        .unwrap();

        let res = migrate(
            deps.as_mut(),
            env,
            MigrateMsg {
                router: cosmos_addr!(ROUTER).to_string(),
                multisig: cosmos_addr!(MULTISIG).to_string(),
                chain_contracts: vec![ChainContracts {
                    chain_name: chain_name.clone(),
                    prover_address: None,
                    gateway_address: nonempty::String::try_from(
                        cosmos_addr!("different_gateway").to_string(),
                    )
                    .unwrap(), // Different gateway
                    verifier_address: nonempty::String::try_from(verifier_addr.to_string())
                        .unwrap(),
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
        let env = mock_env();
        let info = message_info(&cosmos_addr!(SENDER), &[]);

        assert!(old_instantiate(
            deps.as_mut(),
            env.clone(),
            info,
            OldInstantiateMsg {
                governance_address: cosmos_addr!(GOVERNANCE).to_string(),
                service_registry: cosmos_addr!(SERVICE_REGISTRY).to_string(),
            },
        )
        .is_ok());

        let chain_name = chain_name!(CHAIN_1);
        let prover_addr = cosmos_addr!(PROVER_1);
        let gateway_addr = cosmos_addr!(GATEWAY_1);
        let verifier_addr = cosmos_addr!(VERIFIER_1);

        assert!(add_old_prover_registration(
            deps.as_mut(),
            vec![(chain_name.clone(), prover_addr.clone())]
        )
        .is_ok());

        state::save_chain_contracts(
            deps.as_mut().storage,
            chain_name.clone(),
            prover_addr.clone(),
            gateway_addr.clone(),
            verifier_addr.clone(),
        )
        .unwrap();

        assert!(migrate(
            deps.as_mut(),
            env,
            MigrateMsg {
                router: cosmos_addr!(ROUTER).to_string(),
                multisig: cosmos_addr!(MULTISIG).to_string(),
                chain_contracts: vec![ChainContracts {
                    chain_name: chain_name.clone(),
                    prover_address: None,
                    gateway_address: nonempty::String::try_from(gateway_addr.to_string()).unwrap(),
                    verifier_address: nonempty::String::try_from(verifier_addr.to_string())
                        .unwrap(),
                }],
            },
        )
        .is_ok());

        let contracts = state::contracts_by_chain(&deps.storage, chain_name.clone());
        assert!(contracts.is_ok());
        let contracts = contracts.unwrap();

        assert_eq!(contracts.chain_name, chain_name);
        assert_eq!(contracts.prover_address, prover_addr);
        assert_eq!(contracts.gateway_address, gateway_addr);
        assert_eq!(contracts.verifier_address, verifier_addr);

        let contracts_by_prover = state::contracts_by_prover(&deps.storage, prover_addr.clone());
        assert!(contracts_by_prover.is_ok());
        assert_eq!(contracts_by_prover.unwrap().chain_name, chain_name);
    }

    #[test]
    fn migrate_fails_with_duplicate_chain_contracts_present() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = message_info(&cosmos_addr!(SENDER), &[]);

        assert!(old_instantiate(
            deps.as_mut(),
            env.clone(),
            info,
            OldInstantiateMsg {
                governance_address: cosmos_addr!(GOVERNANCE).to_string(),
                service_registry: cosmos_addr!(SERVICE_REGISTRY).to_string(),
            },
        )
        .is_ok());

        let chain_name = chain_name!(CHAIN_1);
        let prover_addr = cosmos_addr!(PROVER_1);
        let gateway_addr = cosmos_addr!(GATEWAY_1);
        let verifier_addr = cosmos_addr!(VERIFIER_1);

        let extra_gateway_addr = cosmos_addr!("extra_gateway");
        let extra_verifier_addr = cosmos_addr!("extra_verifier");

        assert!(add_old_prover_registration(
            deps.as_mut(),
            vec![(chain_name.clone(), prover_addr.clone())]
        )
        .is_ok());

        let res = migrate(
            deps.as_mut(),
            env,
            MigrateMsg {
                router: cosmos_addr!(ROUTER).to_string(),
                multisig: cosmos_addr!(MULTISIG).to_string(),
                chain_contracts: vec![
                    ChainContracts {
                        chain_name: chain_name.clone(),
                        prover_address: None,
                        gateway_address: nonempty::String::try_from(gateway_addr.to_string())
                            .unwrap(),
                        verifier_address: nonempty::String::try_from(verifier_addr.to_string())
                            .unwrap(),
                    },
                    ChainContracts {
                        chain_name: chain_name.clone(),
                        prover_address: None,
                        gateway_address: nonempty::String::try_from(extra_gateway_addr.to_string())
                            .unwrap(),
                        verifier_address: nonempty::String::try_from(
                            extra_verifier_addr.to_string(),
                        )
                        .unwrap(),
                    },
                ],
            },
        );

        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains(&MigrationError::ExtraChainProvided.to_string()));
    }

    #[test]
    fn migrate_can_add_missing_chains() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = message_info(&cosmos_addr!(SENDER), &[]);

        assert!(old_instantiate(
            deps.as_mut(),
            env.clone(),
            info,
            OldInstantiateMsg {
                governance_address: cosmos_addr!(GOVERNANCE).to_string(),
                service_registry: cosmos_addr!(SERVICE_REGISTRY).to_string(),
            },
        )
        .is_ok());

        let chain_name1 = chain_name!(CHAIN_1);
        let chain_name2 = chain_name!(CHAIN_2);
        let prover_addr1 = cosmos_addr!(PROVER_1);
        let prover_addr2 = cosmos_addr!(PROVER_2);
        let gateway_addr1 = cosmos_addr!(GATEWAY_1);
        let verifier_addr1 = cosmos_addr!(VERIFIER_1);
        let gateway_addr2 = cosmos_addr!(GATEWAY_2);
        let verifier_addr2 = cosmos_addr!(VERIFIER_2);

        assert!(add_old_prover_registration(
            deps.as_mut(),
            vec![(chain_name1.clone(), prover_addr1.clone()),]
        )
        .is_ok());

        let res = migrate(
            deps.as_mut(),
            env,
            MigrateMsg {
                router: cosmos_addr!(ROUTER).to_string(),
                multisig: cosmos_addr!(MULTISIG).to_string(),
                chain_contracts: vec![
                    ChainContracts {
                        chain_name: chain_name1.clone(),
                        prover_address: None,
                        gateway_address: nonempty::String::try_from(gateway_addr1.to_string())
                            .unwrap(),
                        verifier_address: nonempty::String::try_from(verifier_addr1.to_string())
                            .unwrap(),
                    },
                    ChainContracts {
                        chain_name: chain_name2.clone(),
                        prover_address: Some(
                            nonempty::String::try_from(prover_addr2.to_string()).unwrap(),
                        ),
                        gateway_address: nonempty::String::try_from(gateway_addr2.to_string())
                            .unwrap(),
                        verifier_address: nonempty::String::try_from(verifier_addr2.to_string())
                            .unwrap(),
                    },
                ],
            },
        );

        assert!(res.is_ok());
    }

    #[test]
    fn migrate_uses_provided_prover_address_over_state_prover() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = message_info(&cosmos_addr!(SENDER), &[]);

        assert!(old_instantiate(
            deps.as_mut(),
            env.clone(),
            info,
            OldInstantiateMsg {
                governance_address: cosmos_addr!(GOVERNANCE).to_string(),
                service_registry: cosmos_addr!(SERVICE_REGISTRY).to_string(),
            },
        )
        .is_ok());

        let chain_name = chain_name!(CHAIN_1);
        let state_prover_addr = cosmos_addr!(PROVER_1);
        let provided_prover_addr = cosmos_addr!(PROVER_2);
        let gateway_addr = cosmos_addr!(GATEWAY_1);
        let verifier_addr = cosmos_addr!(VERIFIER_1);

        assert!(add_old_prover_registration(
            deps.as_mut(),
            vec![(chain_name.clone(), state_prover_addr.clone())]
        )
        .is_ok());

        let res = migrate(
            deps.as_mut(),
            env,
            MigrateMsg {
                router: cosmos_addr!(ROUTER).to_string(),
                multisig: cosmos_addr!(MULTISIG).to_string(),
                chain_contracts: vec![ChainContracts {
                    chain_name: chain_name.clone(),
                    prover_address: Some(
                        nonempty::String::try_from(provided_prover_addr.to_string()).unwrap(),
                    ),
                    gateway_address: nonempty::String::try_from(gateway_addr.to_string()).unwrap(),
                    verifier_address: nonempty::String::try_from(verifier_addr.to_string())
                        .unwrap(),
                }],
            },
        );

        assert!(res.is_ok());

        let contracts = state::contracts_by_chain(&deps.storage, chain_name.clone());
        assert!(contracts.is_ok());
        let contracts = contracts.unwrap();

        assert_eq!(contracts.chain_name, chain_name);
        assert_eq!(contracts.prover_address, provided_prover_addr);
        assert_eq!(contracts.gateway_address, gateway_addr);
        assert_eq!(contracts.verifier_address, verifier_addr);

        let contracts_by_prover =
            state::contracts_by_prover(&deps.storage, provided_prover_addr.clone());
        assert!(contracts_by_prover.is_ok());
        assert_eq!(contracts_by_prover.unwrap().chain_name, chain_name);
    }
}
