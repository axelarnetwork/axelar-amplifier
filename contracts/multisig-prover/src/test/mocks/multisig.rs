use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult, Uint64,
};
use multisig::{
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
    types::MultisigState,
};

pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, StdError> {
    Ok(Response::default())
}

pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, StdError> {
    match msg {
        ExecuteMsg::StartSigningSession { key_id: _, msg: _ } => {
            Ok(Response::new().set_data(to_binary(&Uint64::one())?))
        }
        ExecuteMsg::SubmitSignature {
            session_id: _,
            signature: _,
        } => unimplemented!(),
        ExecuteMsg::KeyGen {
            key_id: _,
            snapshot: _,
            pub_keys: _,
        } => Ok(Response::default()),
    }
}

pub fn query(_deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetMultisig { session_id: _ } => to_binary(&query::query_success()),
        QueryMsg::GetKey { key_id: _ } => unimplemented!(),
    }
}

mod query {
    use multisig::msg::{Multisig, Signer};

    use crate::test::test_data;

    use super::*;

    pub fn query_success() -> Multisig {
        let operators = test_data::operators();
        let quorum = test_data::quorum();

        let signers = operators
            .into_iter()
            .map(|op| Signer {
                address: op.address,
                weight: op.weight.into(),
                pub_key: op.pub_key,
                signature: op.signature,
            })
            .collect::<Vec<Signer>>();

        Multisig {
            state: MultisigState::Completed,
            quorum,
            signers,
        }
    }
}
