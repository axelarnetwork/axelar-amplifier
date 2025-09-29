mod errors;
mod execute;
mod migrations;
mod query;

use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::{address, nonempty, permission_control, FnExt};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, Storage,
};
use error_stack::ResultExt;
use itertools::Itertools;
pub use migrations::{migrate, MigrateMsg};
use msgs_derive::ensure_permissions;

use crate::contract::errors::Error;
use crate::msg::{ExecuteMsg, ExecuteMsgFromProxy, InstantiateMsg, QueryMsg};
use crate::state;

pub const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
pub const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let governance = address::validate_cosmwasm_address(deps.api, &msg.governance_address)?;
    permission_control::set_governance(deps.storage, &governance)?;

    Ok(Response::default())
}

#[ensure_permissions(direct(prover=find_prover_address))]
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::RegisterProtocol {
            service_registry_address: service_registry,
            router_address,
            multisig_address,
        } => {
            let service_registry_addr =
                address::validate_cosmwasm_address(deps.api, &service_registry)?;
            let router_addr = address::validate_cosmwasm_address(deps.api, &router_address)?;
            let multisig_addr = address::validate_cosmwasm_address(deps.api, &multisig_address)?;
            execute::register_protocol(deps, service_registry_addr, router_addr, multisig_addr)
                .change_context(Error::RegisterProtocol)
        }
        ExecuteMsg::RegisterChain {
            chain_name,
            prover_address,
            gateway_address,
            voting_verifier_address,
        } => {
            let prover_address = address::validate_cosmwasm_address(deps.api, &prover_address)?;
            let gateway_address = address::validate_cosmwasm_address(deps.api, &gateway_address)?;
            let voting_verifier_address =
                address::validate_cosmwasm_address(deps.api, &voting_verifier_address)?;

            execute::register_chain(
                deps.storage,
                chain_name.clone(),
                prover_address,
                gateway_address,
                voting_verifier_address,
            )
            .change_context(Error::RegisterChain(chain_name))
        }
        ExecuteMsg::SetActiveVerifiers { verifiers } => {
            let verifiers = verifiers
                .iter()
                .map(|v| address::validate_cosmwasm_address(deps.api, v))
                .try_collect()?;
            execute::set_active_verifier_set(deps, info.sender.clone(), verifiers)
                .change_context(Error::SetActiveVerifiers(info.sender))
        }
        ExecuteMsg::InstantiateChainContracts {
            deployment_name,
            salt,
            params,
        } => execute::instantiate_chain_contracts(deps, env, deployment_name, salt, *params)
            .change_context(Error::InstantiateChainContracts),
        ExecuteMsg::RegisterDeployment { deployment_name } => {
            execute::register_deployment(deps, info.sender, deployment_name.clone())
                .change_context(Error::RegisterDeployment(deployment_name))
        }
    }?
    .then(Ok)
}

fn find_prover_address(
    storage: &dyn Storage,
    sender: &Addr,
    _msg: &ExecuteMsg,
) -> error_stack::Result<bool, state::Error> {
    state::is_prover_registered(storage, sender.clone())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    match msg {
        QueryMsg::ReadyToUnbond {
            verifier_address: worker_address,
        } => {
            let worker_address = address::validate_cosmwasm_address(deps.api, &worker_address)?;

            Ok(to_json_binary(&query::check_verifier_ready_to_unbond(
                deps,
                worker_address,
            )?)?)
        }
        QueryMsg::VerifierInfo {
            service_name,
            verifier,
        } => {
            let verifier_address = address::validate_cosmwasm_address(deps.api, &verifier)?;

            Ok(to_json_binary(&query::verifier_details_with_provers(
                deps,
                service_name,
                verifier_address,
            )?)?)
        }
        QueryMsg::ChainContractsInfo(chain_contracts_key) => Ok(to_json_binary(
            &query::chain_contracts_info(deps, chain_contracts_key)?,
        )?),
        QueryMsg::Instantiate2Address { code_id, salt } => Ok(to_json_binary(
            &query::instantiate2_addr(&deps, &env, code_id, salt.as_slice())
                .change_context(Error::Instantiate2Address)?,
        )?),
        QueryMsg::Deployments { start_after, limit } => Ok(to_json_binary(&query::deployments(
            deps,
            start_after,
            nonempty::Uint32::try_from(limit).change_context(Error::InvalidLimit)?,
        )?)?),
        QueryMsg::Deployment { deployment_name } => {
            Ok(to_json_binary(&query::deployment(deps, deployment_name)?)?)
        }
    }
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::permission_control::Permission;
    use cosmwasm_std::{Addr, StdResult};
    use cw_multi_test::{no_init, App, ContractWrapper, Executor};
    use router_api::{chain_name, cosmos_addr, ChainName};

    use super::*;
    use crate::msg::ChainContractsKey;
    use crate::state::{contracts_by_chain, ChainContractsRecord};

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

        let admin_addr = cosmos_addr!("admin");
        let chain_name = chain_name!("Ethereum");
        let prover = cosmos_addr!("eth_prover");
        let gateway = cosmos_addr!("eth_gateway");
        let verifier = cosmos_addr!("eth_voting_verifier");

        let coordinator_code = ContractWrapper::new(execute, instantiate, query);
        let coordinator_code_id = app.store_code(Box::new(coordinator_code));

        let coordinator_addr = app.instantiate_contract(
            coordinator_code_id,
            admin_addr.clone(),
            &InstantiateMsg {
                governance_address: admin_addr.clone().to_string(),
            },
            &[],
            "Coordinator1.0.0",
            Some(admin_addr.to_string()),
        );

        assert!(coordinator_addr.is_ok());
        let coordinator_addr = coordinator_addr.unwrap();

        app.execute_contract(
            admin_addr.clone(),
            coordinator_addr.clone(),
            &ExecuteMsg::RegisterProtocol {
                service_registry_address: cosmos_addr!("service_registry").to_string(),
                router_address: cosmos_addr!("router").to_string(),
                multisig_address: cosmos_addr!("multisig").to_string(),
            },
            &[],
        )
        .unwrap();

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
        let new_prover = cosmos_addr!("new_eth_prover");
        let new_gateway = cosmos_addr!("new_eth_gateway");
        let new_verifier = cosmos_addr!("new_eth_verifier");

        assert!(test_setup
            .app
            .execute_contract(
                test_setup.admin_addr.clone(),
                test_setup.coordinator_addr.clone(),
                &ExecuteMsg::RegisterChain {
                    chain_name: test_setup.chain_name.clone(),
                    prover_address: new_prover.to_string(),
                    gateway_address: new_gateway.to_string(),
                    voting_verifier_address: new_verifier.to_string(),
                },
                &[]
            )
            .is_ok());

        let chain_prover = contracts_by_chain(
            test_setup
                .app
                .contract_storage(&test_setup.coordinator_addr)
                .as_ref(),
            test_setup.chain_name.clone(),
        );
        assert!(chain_prover.is_ok(), "{:?}", chain_prover);
        let chain_prover = chain_prover.unwrap();
        assert_eq!(chain_prover.prover_address, new_prover);
    }

    #[test]
    fn add_prover_from_random_address_fails() {
        let mut test_setup = setup();
        let new_prover = cosmos_addr!("new_eth_prover");
        let new_gateway = cosmos_addr!("new_eth_gateway");
        let new_verifier = cosmos_addr!("new_eth_verifier");
        let random_addr = cosmos_addr!("random_address");

        let res = test_setup.app.execute_contract(
            random_addr.clone(),
            test_setup.coordinator_addr.clone(),
            &ExecuteMsg::RegisterChain {
                chain_name: test_setup.chain_name.clone(),
                prover_address: new_prover.to_string(),
                gateway_address: new_gateway.to_string(),
                voting_verifier_address: new_verifier.to_string(),
            },
            &[],
        );

        assert!(res.unwrap_err().root_cause().to_string().contains(
            &axelar_wasm_std::error::ContractError::from(
                permission_control::Error::GeneralPermissionDenied {
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
}
