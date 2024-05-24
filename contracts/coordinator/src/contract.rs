use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{Config, CONFIG};
use cosmwasm_std::{entry_point, Empty};
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response};

use crate::error::ContractError;
use crate::execute;
use crate::query;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::ContractError> {
    // any version checks should be done before here

    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    CONFIG.save(
        deps.storage,
        &Config {
            governance: deps.api.addr_validate(&msg.governance_address)?,
        },
    )?;
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    match msg {
        ExecuteMsg::RegisterProverContract {
            chain_name,
            new_prover_addr,
        } => {
            execute::check_governance(&deps, info)?;
            execute::register_prover(deps, chain_name, new_prover_addr)
        }
        ExecuteMsg::SetActiveVerifiers { next_verifier_set } => {
            execute::set_active_worker_set(deps, info, next_verifier_set)
        }
    }
    .map_err(axelar_wasm_std::ContractError::from)
}

#[cfg_attr(not(feature = "library"), entry_point)]
#[allow(dead_code)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    match msg {
        QueryMsg::GetActiveVerifiers { chain_name } => {
            to_json_binary(&query::get_active_verifier_set(deps, chain_name)?)
                .map_err(|err| err.into())
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::error::ContractError;
    use axelar_wasm_std::Participant;
    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{Addr, Empty, HexBinary, OwnedDeps, Uint128};
    use multisig::key::{KeyType, PublicKey};
    use multisig::verifier_set::VerifierSet;
    use router_api::ChainName;
    use tofn::ecdsa::KeyPair;

    use super::*;

    struct TestSetup {
        deps: OwnedDeps<MockStorage, MockApi, MockQuerier, Empty>,
        env: Env,
        prover: Addr,
        chain_name: ChainName,
    }

    fn setup(governance: &str) -> TestSetup {
        let mut deps = mock_dependencies();
        let info = mock_info("instantiator", &[]);
        let env = mock_env();

        let instantiate_msg = InstantiateMsg {
            governance_address: governance.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), instantiate_msg);
        assert!(res.is_ok());

        let eth_prover = Addr::unchecked("eth_prover");
        let eth: ChainName = "Ethereum".to_string().try_into().unwrap();

        TestSetup {
            deps,
            env,
            prover: eth_prover,
            chain_name: eth,
        }
    }

    pub struct Worker {
        pub addr: Addr,
        pub supported_chains: Vec<ChainName>,
        pub key_pair: KeyPair,
    }

    fn create_worker(
        keypair_seed: u32,
        worker_address: Addr,
        supported_chains: Vec<ChainName>,
    ) -> Worker {
        let seed_bytes = keypair_seed.to_be_bytes();
        let mut result = [0; 64];
        result[0..seed_bytes.len()].copy_from_slice(seed_bytes.as_slice());
        let secret_recovery_key = result.as_slice().try_into().unwrap();

        Worker {
            addr: worker_address,
            supported_chains,
            key_pair: tofn::ecdsa::keygen(&secret_recovery_key, b"tofn nonce").unwrap(),
        }
    }

    fn create_worker_set_from_workers(workers: &Vec<Worker>, block_height: u64) -> VerifierSet {
        let mut pub_keys = vec![];
        for worker in workers {
            let encoded_verifying_key =
                HexBinary::from(worker.key_pair.encoded_verifying_key().to_vec());
            let pub_key = PublicKey::try_from((KeyType::Ecdsa, encoded_verifying_key)).unwrap();
            pub_keys.push(pub_key);
        }

        let participants: Vec<Participant> = workers
            .iter()
            .map(|worker| Participant {
                address: worker.addr.clone(),
                weight: Uint128::one().try_into().unwrap(),
            })
            .collect();

        VerifierSet::new(
            participants.clone().into_iter().zip(pub_keys).collect(),
            Uint128::from(participants.len() as u128).mul_ceil((2u64, 3u64)),
            block_height,
        )
    }

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn test_instantiation() {
        let governance = "governance_for_coordinator";
        let test_setup = setup(governance);

        let config = CONFIG.load(test_setup.deps.as_ref().storage).unwrap();
        assert_eq!(config.governance, governance);
    }

    #[test]
    fn migrate_sets_contract_version() {
        let mut deps = mock_dependencies();

        migrate(deps.as_mut(), mock_env(), Empty {}).unwrap();

        let contract_version = cw2::get_contract_version(deps.as_mut().storage).unwrap();
        assert_eq!(contract_version.contract, "coordinator");
        assert_eq!(contract_version.version, CONTRACT_VERSION);
    }

    #[test]
    fn add_prover_from_governance_succeeds() {
        let governance = "governance_for_coordinator";
        let mut test_setup = setup(governance);

        let _res = execute(
            test_setup.deps.as_mut(),
            test_setup.env,
            mock_info(governance, &[]),
            ExecuteMsg::RegisterProverContract {
                chain_name: test_setup.chain_name.clone(),
                new_prover_addr: test_setup.prover.clone(),
            },
        )
        .unwrap();

        let chain_provers =
            query::provers(test_setup.deps.as_ref(), test_setup.chain_name.clone()).unwrap();
        assert_eq!(chain_provers, test_setup.prover);
    }

    #[test]
    fn add_prover_from_random_address_fails() {
        let governance = "governance_for_coordinator";
        let mut test_setup = setup(governance);

        let res = execute(
            test_setup.deps.as_mut(),
            test_setup.env,
            mock_info("random_address", &[]),
            ExecuteMsg::RegisterProverContract {
                chain_name: test_setup.chain_name.clone(),
                new_prover_addr: test_setup.prover.clone(),
            },
        );
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::ContractError::from(ContractError::Unauthorized).to_string()
        );
    }

    #[test]
    fn set_and_get_populated_active_worker_set_success() {
        let governance = "governance_for_coordinator";
        let mut test_setup = setup(governance);

        let new_worker = create_worker(
            1,
            Addr::unchecked("worker1"),
            vec![test_setup.chain_name.clone()],
        );
        let new_verifier_set =
            create_worker_set_from_workers(&vec![new_worker], test_setup.env.block.height);

        let res = execute(
            test_setup.deps.as_mut(),
            test_setup.env.clone(),
            mock_info(governance, &[]),
            ExecuteMsg::RegisterProverContract {
                chain_name: test_setup.chain_name.clone(),
                new_prover_addr: test_setup.prover.clone(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            test_setup.deps.as_mut(),
            test_setup.env.clone(),
            mock_info(test_setup.prover.as_ref(), &[]),
            ExecuteMsg::SetActiveVerifiers {
                next_verifier_set: new_verifier_set.clone(),
            },
        );
        assert!(res.is_ok());

        let eth_active_worker_set =
            query::get_active_verifier_set(test_setup.deps.as_ref(), test_setup.chain_name.clone())
                .unwrap();

        assert_eq!(eth_active_worker_set, Some(new_verifier_set));
    }

    #[test]
    fn set_and_get_empty_active_worker_set_success() {
        let governance = "governance_for_coordinator";
        let mut test_setup = setup(governance);

        let _response = execute(
            test_setup.deps.as_mut(),
            test_setup.env,
            mock_info(governance, &[]),
            ExecuteMsg::RegisterProverContract {
                chain_name: test_setup.chain_name.clone(),
                new_prover_addr: test_setup.prover.clone(),
            },
        );

        let query_result =
            query::get_active_verifier_set(test_setup.deps.as_ref(), test_setup.chain_name.clone())
                .unwrap();

        assert_eq!(query_result, None);
    }
}
