use std::collections::HashMap;

use anyhow::Error;
use command_batcher::msg::{ExecuteMsg, GetProofResponse, ProofStatus, QueryMsg};
use cosmwasm_std::{Addr, HexBinary, StdResult};
use cw_multi_test::{AppResponse, Executor};
use ethabi::{ParamType, Token};
use setup::{setup_test_case, TestCaseConfig};

mod mocks;
mod setup;

// TODO: Improve module usage
#[path = "../src/test/test_data.rs"]
mod test_data;

const RELAYER: &str = "relayer";
const PROOF_ID: &str = "95eff19658ffef7099536bbff91d83e7fb17aa16aabaeb32b905417a259074ce";

fn execute_key_gen(
    test_case: &mut TestCaseConfig,
    pub_keys: Option<HashMap<String, HexBinary>>,
) -> Result<AppResponse, Error> {
    let pub_keys = match pub_keys {
        Some(keys) => keys,
        None => test_data::operators()
            .into_iter()
            .map(|op| (op.address.to_string(), op.pub_key.into()))
            .collect::<HashMap<String, HexBinary>>(),
    };

    let msg = ExecuteMsg::RotateSnapshot { pub_keys };
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
    proof_id: Option<String>,
) -> StdResult<GetProofResponse> {
    let proof_id = match proof_id {
        Some(id) => id,
        None => PROOF_ID.to_string(),
    };

    test_case.app.wrap().query_wasm_smart(
        test_case.prover_address.clone(),
        &QueryMsg::GetProof { proof_id },
    )
}

#[test]
fn test_key_gen() {
    let mut test_case = setup_test_case();
    let res = execute_key_gen(&mut test_case, None);

    assert!(res.is_ok());
}

#[test]
fn test_construct_proof() {
    let mut test_case = setup_test_case();
    execute_key_gen(&mut test_case, None).unwrap();

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
    execute_key_gen(&mut test_case, None).unwrap();
    execute_construct_proof(&mut test_case, None).unwrap();

    let res = query_get_proof(&mut test_case, None).unwrap();

    assert_eq!(res.proof_id.to_string(), PROOF_ID);
    assert_eq!(res.message_ids.len(), 2);
    assert_eq!(res.proof.encode(), test_data::encoded_proof());
    match res.status {
        ProofStatus::Completed { execute_data } => {
            let tokens = ethabi::decode(
                &[ParamType::Bytes, ParamType::Bytes],
                execute_data.as_slice(),
            )
            .unwrap();

            assert_eq!(
                tokens,
                vec![
                    Token::Bytes(res.data.encode().to_vec()),
                    Token::Bytes(res.proof.encode().to_vec())
                ]
            );
        } // TODO: Check execute data
        _ => panic!("Expected proof status to be completed"), // multisig mock will always return completed multisig
    }
}
