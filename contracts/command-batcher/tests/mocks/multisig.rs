use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult, Uint64,
};
use multisig::{
    msg::{ExecuteMsg, GetSigningSessionResponse, InstantiateMsg, QueryMsg},
    types::MultisigState,
};

use super::test_data;

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
        QueryMsg::GetSigningSession { session_id: _ } => to_binary(&query::query_success()),
    }
}

mod query {
    use axelar_wasm_std::{nonempty, Participant, Snapshot};
    use cosmwasm_std::Timestamp;

    use super::*;

    pub fn query_success() -> GetSigningSessionResponse {
        let operators = test_data::operators();

        let timestamp: nonempty::Timestamp = Timestamp::from_nanos(1).try_into().unwrap();
        let height = nonempty::Uint64::try_from(test_data::block_height()).unwrap();

        let threshold = test_data::threshold();

        let participants = operators
            .iter()
            .map(|op| Participant {
                address: op.address.clone(),
                weight: op.weight.try_into().unwrap(),
            })
            .collect::<Vec<Participant>>()
            .try_into()
            .unwrap();

        let snapshot = Snapshot::new(timestamp.clone(), height.clone(), threshold, participants);

        let signatures = operators
            .iter()
            .filter(|op| op.signature.is_some())
            .map(|op| (op.address.to_string(), op.signature.clone().unwrap()))
            .collect();

        let pub_keys = operators
            .iter()
            .map(|op| (op.address.to_string(), op.pub_key.clone()))
            .collect();

        GetSigningSessionResponse {
            state: MultisigState::Completed,
            signatures,
            snapshot,
            pub_keys,
        }
    }
}
