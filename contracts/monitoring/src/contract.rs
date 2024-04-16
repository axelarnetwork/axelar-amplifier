use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{Config, CONFIG};
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response};

use crate::error::ContractError;
use crate::execute;
use crate::query;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
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
        ExecuteMsg::RegisterActiveWorkerSet { next_worker_set } => {
            // TODO: add check_prover to make sure prover is part of the system
            execute::register_active_worker_set(deps, info, next_worker_set)
        }
    }
    .map_err(axelar_wasm_std::ContractError::from)
}

#[cfg_attr(not(feature = "library"), entry_point)]
#[allow(dead_code)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    match msg {
        QueryMsg::GetActiveWorkerSet { prover_address } => {
            to_binary(&query::get_active_worker_set(deps, prover_address)?)
                .map_err(|err| err.into())
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::error::ContractError;
    use axelar_wasm_std::Participant;
    use connection_router_api::ChainName;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{Addr, HexBinary, Uint256};
    use multisig::key::{KeyType, PublicKey};
    use multisig::worker_set::WorkerSet;
    use tofn::ecdsa::KeyPair;

    use super::*;

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

    fn create_worker_set_from_workers(workers: &Vec<Worker>, block_height: u64) -> WorkerSet {
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
                weight: Uint256::one().try_into().unwrap(),
            })
            .collect();

        WorkerSet::new(
            participants.clone().into_iter().zip(pub_keys).collect(),
            Uint256::from_u128(participants.len() as u128).mul_ceil((2u64, 3u64)),
            block_height,
        )
    }

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn test_instantiation() {
        let governance = "governance_for_monitoring";
        let mut deps = mock_dependencies();
        let info = mock_info("instantiator", &[]);
        let env = mock_env();

        let res = instantiate(
            deps.as_mut(),
            env,
            info,
            InstantiateMsg {
                governance_address: governance.to_string(),
            },
        );
        assert!(res.is_ok());

        let config = CONFIG.load(deps.as_ref().storage).unwrap();
        assert_eq!(config.governance, governance);
    }

    #[test]
    fn add_prover_from_governance_succeeds() {
        let governance = "governance_for_monitoring";
        let mut deps = mock_dependencies();
        let info = mock_info("instantiator", &[]);
        let env = mock_env();

        let _ = instantiate(
            deps.as_mut(),
            env.clone(),
            info,
            InstantiateMsg {
                governance_address: governance.to_string(),
            },
        );

        let eth_prover = Addr::unchecked("eth_prover");
        let eth: ChainName = "Ethereum".to_string().try_into().unwrap();
        let msg = ExecuteMsg::RegisterProverContract {
            chain_name: eth.clone(),
            new_prover_addr: eth_prover.clone(),
        };
        let _res = execute(deps.as_mut(), mock_env(), mock_info(governance, &[]), msg).unwrap();
        let chain_provers = query::provers(deps.as_ref(), eth.clone()).unwrap();
        assert_eq!(chain_provers, vec![eth_prover]);
    }

    #[test]
    fn add_prover_from_random_address_fails() {
        let governance = "governance_for_monitoring";
        let mut deps = mock_dependencies();
        let info = mock_info("instantiator", &[]);
        let env = mock_env();

        let _ = instantiate(
            deps.as_mut(),
            env.clone(),
            info,
            InstantiateMsg {
                governance_address: governance.to_string(),
            },
        );

        let eth_prover = Addr::unchecked("eth_prover");
        let eth: ChainName = "Ethereum".to_string().try_into().unwrap();
        let msg = ExecuteMsg::RegisterProverContract {
            chain_name: eth.clone(),
            new_prover_addr: eth_prover.clone(),
        };
        let res = execute(
            deps.as_mut(),
            env.clone(),
            mock_info("random_address", &[]),
            msg,
        );
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::ContractError::from(ContractError::Unauthorized).to_string()
        );
    }

    #[test]
    fn set_and_get_populated_active_worker_set_success() {
        let governance = "governance_for_monitoring";
        let mut deps = mock_dependencies();
        let info = mock_info("instantiator", &[]);
        let env = mock_env();

        let _ = instantiate(
            deps.as_mut(),
            env.clone(),
            info,
            InstantiateMsg {
                governance_address: governance.to_string(),
            },
        );

        let eth_prover = Addr::unchecked("eth_prover");
        let eth: ChainName = "Ethereum".to_string().try_into().unwrap();

        let new_worker = create_worker(1, Addr::unchecked("worker1"), vec![eth]);
        let new_worker_set = create_worker_set_from_workers(&vec![new_worker], env.block.height);

        let _res = execute(
            deps.as_mut(),
            env.clone(),
            mock_info(eth_prover.as_ref(), &[]),
            ExecuteMsg::RegisterActiveWorkerSet {
                next_worker_set: new_worker_set.clone(),
            },
        );

        let eth_active_worker_set =
            query::get_active_worker_set(deps.as_ref(), eth_prover.clone()).unwrap();

        assert_eq!(eth_active_worker_set, new_worker_set);
    }

    #[test]
    fn set_and_get_empty_active_worker_set_success() {
        let governance = "governance_for_monitoring";
        let mut deps = mock_dependencies();
        let info = mock_info("instantiator", &[]);
        let env = mock_env();

        let _ = instantiate(
            deps.as_mut(),
            env.clone(),
            info,
            InstantiateMsg {
                governance_address: governance.to_string(),
            },
        );

        let eth_prover = Addr::unchecked("eth_prover");
        let eth: ChainName = "Ethereum".to_string().try_into().unwrap();
        let msg = ExecuteMsg::RegisterProverContract {
            chain_name: eth.clone(),
            new_prover_addr: eth_prover.clone(),
        };
        let _response =
            execute(deps.as_mut(), mock_env(), mock_info(governance, &[]), msg).unwrap();

        let query_result = query::get_active_worker_set(deps.as_ref(), eth_prover.clone());

        assert_eq!(
            query_result.unwrap_err().to_string(),
            axelar_wasm_std::ContractError::from(ContractError::NoActiveWorkerSetRegistered)
                .to_string()
        );
    }
}
