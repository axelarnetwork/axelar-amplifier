use cosmwasm_std::{
    to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult, Uint64,
};
use cw_multi_test::{App, Executor};
use cw_storage_plus::Map;
use multisig::key::{KeyType, KeyTyped, PublicKey};
use multisig::{
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
    types::MultisigState,
};

use crate::test::test_data::TestOperator;

use self::query::get_public_key_query_success;

pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, StdError> {
    Ok(Response::default())
}

pub const PUB_KEYS: Map<(String, KeyType), PublicKey> = Map::new("registered_pub_keys");
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, StdError> {
    match msg {
        ExecuteMsg::StartSigningSession {
            worker_set_id: _,
            msg: _,
            sig_verifier: _,
            chain_name: _,
        } => Ok(Response::new().set_data(to_binary(&Uint64::one())?)),
        ExecuteMsg::SubmitSignature {
            session_id: _,
            signature: _,
        } => unimplemented!(),
        ExecuteMsg::RegisterWorkerSet { worker_set: _ } => Ok(Response::default()),
        ExecuteMsg::RegisterPublicKey { public_key } => {
            PUB_KEYS.save(
                deps.storage,
                (info.sender.to_string(), public_key.key_type()),
                &public_key,
            )?;
            Ok(Response::default())
        }
        ExecuteMsg::AuthorizeCaller {
            contract_address: _,
        } => Ok(Response::default()),
        ExecuteMsg::UnauthorizeCaller {
            contract_address: _,
        } => Ok(Response::default()),
    }
}

pub fn register_pub_keys(app: &mut App, multisig_address: Addr, workers: Vec<TestOperator>) {
    for worker in workers {
        app.execute_contract(
            worker.address,
            multisig_address.clone(),
            &ExecuteMsg::RegisterPublicKey {
                public_key: worker.pub_key.into(),
            },
            &[],
        )
        .unwrap();
    }
}

pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetMultisig { session_id: _ } => to_binary(&query::query_success()),
        QueryMsg::GetWorkerSet { worker_set_id: _ } => unimplemented!(),
        QueryMsg::GetPublicKey {
            worker_address,
            key_type,
        } => to_binary(&get_public_key_query_success(
            deps,
            worker_address,
            key_type,
        )),
    }
}

mod query {
    use multisig::key::PublicKey;
    use multisig::msg::{Multisig, Signer};

    use crate::test::test_data;

    use super::*;

    pub fn query_success() -> Multisig {
        let operators = test_data::operators();
        let quorum = test_data::quorum();

        let signers = operators
            .into_iter()
            .map(|op| {
                (
                    Signer {
                        address: op.address,
                        weight: op.weight.into(),
                        pub_key: op.pub_key,
                    },
                    op.signature,
                )
            })
            .collect::<Vec<_>>();

        Multisig {
            state: MultisigState::Completed {
                completed_at: 12345,
            },
            quorum,
            signers,
        }
    }
    pub fn get_public_key_query_success(
        deps: Deps,
        worker: String,
        key_type: KeyType,
    ) -> PublicKey {
        PUB_KEYS
            .load(deps.storage, (worker, key_type.clone()))
            .unwrap()
    }
}
