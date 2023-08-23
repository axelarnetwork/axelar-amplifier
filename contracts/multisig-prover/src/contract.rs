#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Reply, Response, StdResult,
};

use std::str::FromStr;

use connection_router::types::ChainName;

use crate::{
    error::ContractError,
    execute,
    msg::ExecuteMsg,
    msg::{InstantiateMsg, QueryMsg},
    query, reply,
    state::{Config, CONFIG},
};

pub const START_MULTISIG_REPLY_ID: u64 = 1;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let admin = deps.api.addr_validate(&msg.admin_address)?;
    let gateway = deps.api.addr_validate(&msg.gateway_address)?;
    let multisig = deps.api.addr_validate(&msg.multisig_address)?;
    let service_registry = deps.api.addr_validate(&msg.service_registry_address)?;

    let config = Config {
        admin,
        gateway,
        multisig,
        service_registry,
        destination_chain_id: msg.destination_chain_id,
        signing_threshold: msg.signing_threshold,
        service_name: msg.service_name,
        chain_name: ChainName::from_str(&msg.chain_name)
            .map_err(|_| ContractError::InvalidChainName)?,
    };

    CONFIG.save(deps.storage, &config)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::ConstructProof { message_ids } => execute::construct_proof(deps, message_ids),
        ExecuteMsg::RotateSnapshot { pub_keys, key_id } => {
            let config = CONFIG.load(deps.storage)?;
            if config.admin != info.sender {
                return Err(ContractError::Unauthorized);
            }

            execute::rotate_snapshot(deps, env, config, pub_keys, key_id)
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(deps: DepsMut, _env: Env, reply: Reply) -> Result<Response, ContractError> {
    match reply.id {
        START_MULTISIG_REPLY_ID => reply::start_multisig_reply(deps, reply),
        _ => unreachable!("unknown reply ID"),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetProof {
            multisig_session_id,
        } => to_binary(&query::get_proof(deps, multisig_session_id)?),
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use anyhow::Error;
    use cosmwasm_std::{
        testing::{mock_dependencies, mock_env, mock_info},
        Addr, Fraction, HexBinary, Uint256, Uint64,
    };
    use cw_multi_test::{AppResponse, Executor};
    use ethabi::{ParamType, Token};

    use crate::{
        msg::{GetProofResponse, ProofStatus},
        test::{
            multicontract::{setup_test_case, TestCaseConfig},
            test_data,
        },
    };

    use super::*;

    const RELAYER: &str = "relayer";
    const MULTISIG_SESSION_ID: Uint64 = Uint64::one();

    fn execute_key_gen(
        test_case: &mut TestCaseConfig,
        pub_keys: Option<HashMap<String, HexBinary>>,
        key_id: Option<String>,
    ) -> Result<AppResponse, Error> {
        let pub_keys = match pub_keys {
            Some(keys) => keys,
            None => test_data::operators()
                .into_iter()
                .map(|op| (op.address.to_string(), op.pub_key.into()))
                .collect::<HashMap<String, HexBinary>>(),
        };

        let key_id = match key_id {
            Some(id) => id,
            None => "key_id".to_string(),
        };

        let msg = ExecuteMsg::RotateSnapshot { pub_keys, key_id };
        test_case.app.execute_contract(
            test_case.admin.clone(),
            test_case.prover_address.clone(),
            &msg,
            &[],
        )
    }

    fn execute_construct_proof(
        test_case: &mut TestCaseConfig,
        message_ids: Option<Vec<String>>,
    ) -> Result<AppResponse, Error> {
        let message_ids = match message_ids {
            Some(ids) => ids,
            None => test_data::messages()
                .into_iter()
                .map(|msg| msg.id.to_string())
                .collect::<Vec<String>>(),
        };

        let msg = ExecuteMsg::ConstructProof { message_ids };
        test_case.app.execute_contract(
            Addr::unchecked(RELAYER),
            test_case.prover_address.clone(),
            &msg,
            &[],
        )
    }

    fn query_get_proof(
        test_case: &mut TestCaseConfig,
        multisig_session_id: Option<Uint64>,
    ) -> StdResult<GetProofResponse> {
        let multisig_session_id = match multisig_session_id {
            Some(id) => id,
            None => MULTISIG_SESSION_ID,
        };

        test_case.app.wrap().query_wasm_smart(
            test_case.prover_address.clone(),
            &QueryMsg::GetProof {
                multisig_session_id,
            },
        )
    }

    #[test]
    fn test_instantiation() {
        let instantiator = "instantiator";
        let admin = "admin";
        let gateway_address = "gateway_address";
        let multisig_address = "multisig_address";
        let service_registry_address = "service_registry_address";
        let destination_chain_id = Uint256::one();
        let signing_threshold = (
            test_data::threshold().numerator(),
            test_data::threshold().denominator(),
        )
            .try_into()
            .unwrap();
        let service_name = "service_name";

        let mut deps = mock_dependencies();
        let info = mock_info(&instantiator, &[]);
        let env = mock_env();

        let msg = InstantiateMsg {
            admin_address: admin.to_string(),
            gateway_address: gateway_address.to_string(),
            multisig_address: multisig_address.to_string(),
            service_registry_address: service_registry_address.to_string(),
            destination_chain_id,
            signing_threshold,
            service_name: service_name.to_string(),
            chain_name: "Ethereum".to_string(),
        };

        let res = instantiate(deps.as_mut(), env, info, msg);

        assert!(res.is_ok());
        let res = res.unwrap();

        assert_eq!(res.messages.len(), 0);

        let config = CONFIG.load(deps.as_ref().storage).unwrap();
        assert_eq!(config.admin, admin);
        assert_eq!(config.gateway, gateway_address);
        assert_eq!(config.multisig, multisig_address);
        assert_eq!(config.service_registry, service_registry_address);
        assert_eq!(config.destination_chain_id, destination_chain_id);
        assert_eq!(
            config.signing_threshold,
            signing_threshold.try_into().unwrap()
        );
        assert_eq!(config.service_name, service_name);
    }

    #[test]
    fn test_key_gen() {
        let mut test_case = setup_test_case();
        let res = execute_key_gen(&mut test_case, None, None);

        assert!(res.is_ok());
    }

    #[test]
    fn test_construct_proof() {
        let mut test_case = setup_test_case();
        execute_key_gen(&mut test_case, None, None).unwrap();

        let res = execute_construct_proof(&mut test_case, None).unwrap();

        let event = res
            .events
            .iter()
            .find(|event| event.ty == "wasm-proof_under_construction");

        assert!(event.is_some());
    }

    #[test]
    fn test_query_proof() {
        let mut test_case = setup_test_case();
        execute_key_gen(&mut test_case, None, None).unwrap();
        execute_construct_proof(&mut test_case, None).unwrap();

        let res = query_get_proof(&mut test_case, None).unwrap();

        assert_eq!(res.multisig_session_id, MULTISIG_SESSION_ID);
        assert_eq!(res.message_ids.len(), 2);
        match res.status {
            ProofStatus::Completed { execute_data } => {
                let tokens =
                    ethabi::decode(&[ParamType::Bytes], &execute_data.as_slice()[4..]).unwrap();

                let input = match tokens[0].clone() {
                    Token::Bytes(input) => input,
                    _ => panic!("Invalid proof"),
                };

                let tokens =
                    ethabi::decode(&[ParamType::Bytes, ParamType::Bytes], input.as_slice())
                        .unwrap();

                assert_eq!(
                    tokens,
                    vec![
                        Token::Bytes(res.data.encode().to_vec()),
                        Token::Bytes(test_data::encoded_proof().to_vec())
                    ]
                );
            }
            _ => panic!("Expected proof status to be completed"), // multisig mock will always return completed multisig
        }
    }
}
