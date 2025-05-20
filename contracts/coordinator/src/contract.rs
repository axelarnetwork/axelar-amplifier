mod execute;
mod migrations;
mod query;

use axelar_wasm_std::address::validate_cosmwasm_address;
use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::{address, permission_control, FnExt, IntoContractError};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, Storage,
};
use error_stack::{report, ResultExt};
use itertools::Itertools;
pub use migrations::{migrate, MigrateMsg};

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{is_prover_registered, Config, CONFIG};

pub const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
pub const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("coordinator instantiation failed")]
    Instantiate,
    #[error("coordinator query failed")]
    Query,
    #[error("coordinator execution failed")]
    Execute,
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)
        .map_err(|err| error_stack::Report::new(err))
        .change_context(Error::Instantiate)?;

    let config = Config {
        service_registry: address::validate_cosmwasm_address(deps.api, &msg.service_registry)?,
        router: address::validate_cosmwasm_address(deps.api, &msg.router_address)?,
        multisig: address::validate_cosmwasm_address(deps.api, &msg.multisig_address)?,
    };
    CONFIG
        .save(deps.storage, &config)
        .map_err(|err| error_stack::Report::new(err))
        .change_context(Error::Instantiate)?;

    let governance = address::validate_cosmwasm_address(deps.api, &msg.governance_address)
        .change_context(Error::Instantiate)?;

    permission_control::set_governance(deps.storage, &governance)
        .map_err(|err| error_stack::Report::new(err))
        .change_context(Error::Instantiate)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg
        .ensure_permissions(
            deps.storage,
            &info.sender,
            find_prover_address(&info.sender),
        )
        .change_context(Error::Execute)?
    {
        ExecuteMsg::RegisterProverContract {
            chain_name,
            new_prover_addr,
        } => {
            let new_prover_addr = validate_cosmwasm_address(deps.api, &new_prover_addr)?;
            execute::register_prover(deps, chain_name, new_prover_addr)
        }
        ExecuteMsg::RegisterChain {
            chain_name,
            prover_address,
            gateway_address,
            voting_verifier_address,
        } => {
            let prover_address = validate_cosmwasm_address(deps.api, &prover_address)?;

            let gateway_address = validate_cosmwasm_address(deps.api, &gateway_address)?;

            let voting_verifier_address =
                validate_cosmwasm_address(deps.api, &voting_verifier_address)?;

            execute::register_chain(
                deps,
                chain_name,
                prover_address,
                gateway_address,
                voting_verifier_address,
            )
        }
        ExecuteMsg::SetActiveVerifiers { verifiers } => {
            let verifiers = verifiers
                .iter()
                .map(|v| validate_cosmwasm_address(deps.api, v))
                .try_collect()?;
            execute::set_active_verifier_set(deps, info, verifiers)
        }
        ExecuteMsg::InstantiateChainContracts {
            deployment_name,
            params,
        } => execute::instantiate_chain_contracts(deps, env, info, deployment_name, &params),
    }
    .change_context(Error::Execute)?
    .then(Ok)
}

fn find_prover_address(
    sender: &Addr,
) -> impl FnOnce(&dyn Storage, &ExecuteMsg) -> error_stack::Result<Addr, crate::state::Error> + '_ {
    |storage, _| {
        if is_prover_registered(storage, sender.clone())? {
            Ok(sender.clone())
        } else {
            Err(report!(crate::state::Error::ProverNotRegistered(
                sender.clone()
            )))
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    match msg {
        QueryMsg::ReadyToUnbond {
            verifier_address: worker_address,
        } => {
            let worker_address = validate_cosmwasm_address(deps.api, &worker_address)?;

            Ok(to_json_binary(&query::check_verifier_ready_to_unbond(
                deps,
                worker_address,
            )?)?)
        }
        QueryMsg::VerifierInfo {
            service_name,
            verifier,
        } => {
            let verifier_address = validate_cosmwasm_address(deps.api, &verifier)?;

            Ok(to_json_binary(&query::verifier_details_with_provers(
                deps,
                service_name,
                verifier_address,
            )?)?)
        }
        QueryMsg::ChainContractsInfo(chain_contracts_key) => Ok(to_json_binary(
            &query::get_chain_contracts_info(deps, chain_contracts_key)?,
        )?),
    }
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::permission_control::Permission;
    use cosmwasm_std::{Addr, StdResult};
    use cw_multi_test::{no_init, App, ContractWrapper, Executor};
    use router_api::ChainName;

    use super::*;
    use crate::msg::ChainContractsKey;
    use crate::state::{load_prover_by_chain, ChainContractsRecord};

    struct TestSetup {
        admin_addr: Addr,
        coordinator_addr: Addr,
        app: App,
        prover: Addr,
        gateway: Addr,
        verifier: Addr,
        chain_name: ChainName,
    }

    fn setup() -> TestSetup {
        let mut app = App::new(no_init);

        let admin_addr = app.api().addr_make("admin");
        let chain_name: ChainName = "Ethereum".parse().unwrap();
        let prover = app.api().addr_make("eth_prover");
        let gateway = app.api().addr_make("eth_gateway");
        let verifier = app.api().addr_make("eth_voting_verifier");

        let coordinator_code = ContractWrapper::new(execute, instantiate, query);
        let coordinator_code_id = app.store_code(Box::new(coordinator_code));

        let coordinator_addr = app.instantiate_contract(
            coordinator_code_id,
            admin_addr.clone(),
            &InstantiateMsg {
                governance_address: admin_addr.clone().to_string(),
                service_registry: app.api().addr_make("service_registry").to_string(),
                router_address: app.api().addr_make("router").to_string(),
                multisig_address: app.api().addr_make("multisig").to_string(),
            },
            &[],
            "Coordinator1.0.0",
            Some(admin_addr.to_string()),
        );

        assert!(coordinator_addr.is_ok());
        let coordinator_addr = coordinator_addr.unwrap();

        let res = app.execute_contract(
            admin_addr.clone(),
            coordinator_addr.clone(),
            &ExecuteMsg::RegisterChain {
                chain_name: chain_name.clone(),
                prover_address: prover.clone().to_string(),
                gateway_address: gateway.clone().to_string(),
                voting_verifier_address: verifier.clone().to_string(),
            },
            &[],
        );

        assert!(res.is_ok());

        TestSetup {
            admin_addr,
            coordinator_addr,
            app,
            chain_name: chain_name.clone(),
            prover: prover.clone(),
            gateway: gateway.clone(),
            verifier: verifier.clone(),
        }
    }

    #[test]
    fn add_prover_from_governance_succeeds() {
        let mut test_setup = setup();
        let new_prover = test_setup.app.api().addr_make("new_eth_prover");

        assert!(test_setup
            .app
            .execute_contract(
                test_setup.admin_addr.clone(),
                test_setup.coordinator_addr.clone(),
                &ExecuteMsg::RegisterProverContract {
                    chain_name: test_setup.chain_name.clone(),
                    new_prover_addr: new_prover.to_string(),
                },
                &[]
            )
            .is_ok());

        let chain_prover = load_prover_by_chain(
            test_setup
                .app
                .contract_storage(&test_setup.coordinator_addr)
                .as_ref(),
            test_setup.chain_name.clone(),
        );
        assert!(chain_prover.is_ok(), "{:?}", chain_prover);
        assert_eq!(chain_prover.unwrap(), new_prover);
    }

    #[test]
    fn add_prover_from_random_address_fails() {
        let mut test_setup = setup();
        let new_prover = test_setup.app.api().addr_make("new_eth_prover");
        let random_addr = test_setup.app.api().addr_make("random_address");

        let res = test_setup.app.execute_contract(
            random_addr.clone(),
            test_setup.coordinator_addr.clone(),
            &ExecuteMsg::RegisterProverContract {
                chain_name: test_setup.chain_name.clone(),
                new_prover_addr: new_prover.to_string(),
            },
            &[],
        );

        assert!(res.unwrap_err().root_cause().to_string().contains(
            &axelar_wasm_std::error::ContractError::from(
                permission_control::Error::PermissionDenied {
                    expected: Permission::Governance.into(),
                    actual: Permission::NoPrivilege.into()
                }
            )
            .to_string()
        ));
    }

    #[test]
    fn register_contract_addresses_from_governance_succeeds() {
        let test_setup = setup();

        let record_response_by_chain: StdResult<ChainContractsRecord> =
            test_setup.app.wrap().query_wasm_smart(
                test_setup.coordinator_addr.clone(),
                &QueryMsg::ChainContractsInfo(ChainContractsKey::ChainName(test_setup.chain_name)),
            );

        assert!(record_response_by_chain.is_ok());
        goldie::assert_json!(record_response_by_chain.unwrap());

        let record_response_by_gateway: StdResult<ChainContractsRecord> =
            test_setup.app.wrap().query_wasm_smart(
                test_setup.coordinator_addr.clone(),
                &QueryMsg::ChainContractsInfo(ChainContractsKey::GatewayAddress(
                    test_setup.gateway.clone(),
                )),
            );

        assert!(record_response_by_gateway.is_ok());
        goldie::assert_json!(record_response_by_gateway.unwrap());

        let record_response_by_prover: StdResult<ChainContractsRecord> =
            test_setup.app.wrap().query_wasm_smart(
                test_setup.coordinator_addr.clone(),
                &QueryMsg::ChainContractsInfo(ChainContractsKey::ProverAddress(
                    test_setup.prover.clone(),
                )),
            );

        assert!(record_response_by_prover.is_ok());
        goldie::assert_json!(record_response_by_prover.unwrap());

        let record_response_by_verifier: StdResult<ChainContractsRecord> =
            test_setup.app.wrap().query_wasm_smart(
                test_setup.coordinator_addr.clone(),
                &QueryMsg::ChainContractsInfo(ChainContractsKey::VerifierAddress(
                    test_setup.verifier.clone(),
                )),
            );

        assert!(record_response_by_verifier.is_ok());
        goldie::assert_json!(record_response_by_verifier.unwrap());
    }

    #[test]
    fn migrate_sets_contract_version() {
        let mut test_setup = setup();

        let coordinator_code =
            ContractWrapper::new(execute, instantiate, query).with_migrate(migrate);
        let coordinator_code_id = test_setup.app.store_code(Box::new(coordinator_code));

        assert!(test_setup
            .app
            .migrate_contract(
                test_setup.admin_addr.clone(),
                test_setup.coordinator_addr.clone(),
                &MigrateMsg {
                    router: test_setup.app.api().addr_make("router"),
                    multisig: test_setup.app.api().addr_make("multisig"),
                },
                coordinator_code_id,
            )
            .is_ok());

        let contract_version = cw2::get_contract_version(
            test_setup
                .app
                .contract_storage_mut(&test_setup.coordinator_addr)
                .as_ref(),
        )
        .unwrap();
        assert_eq!(contract_version.contract, CONTRACT_NAME);
        assert_eq!(contract_version.version, CONTRACT_VERSION);
    }
}
