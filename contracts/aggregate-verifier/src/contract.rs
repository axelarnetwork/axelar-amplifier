#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_binary, Binary, Deps, DepsMut, Env, MessageInfo, Reply, Response, StdError, StdResult,
};
use cw_utils::{parse_reply_execute_data, MsgExecuteContractResponse};

use crate::{
    error::ContractError,
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
    state::{Config, CONFIG},
};

use connection_router::state::Message;

use self::execute::verify_messages;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let voting_verifier = deps.api.addr_validate(&msg.voting_verifier_address)?;
    CONFIG.save(deps.storage, &Config { voting_verifier })?;

    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::VerifyMessages { messages } => {
            let msgs = messages
                .into_iter()
                .map(Message::try_from)
                .collect::<Result<Vec<Message>, _>>()?;

            verify_messages(deps, msgs)
        }
    }
}

pub mod execute {

    use cosmwasm_std::{to_binary, SubMsg, WasmMsg};

    use super::*;

    pub fn verify_messages(deps: DepsMut, msgs: Vec<Message>) -> Result<Response, ContractError> {
        // Simply pass through to the voting verifier for now. If there are multiple verification
        // methods in the future, as well as support for a callback when a message is actually
        // verified, we can store the verification status. But for now, simple pass through works
        let voting_verifier = CONFIG.load(deps.storage)?.voting_verifier;
        Ok(Response::new().add_submessage(SubMsg::reply_on_success(
            WasmMsg::Execute {
                contract_addr: voting_verifier.to_string(),
                msg: to_binary(&ExecuteMsg::VerifyMessages {
                    messages: msgs
                        .into_iter()
                        .map(connection_router::msg::Message::from)
                        .collect(),
                })?,
                funds: vec![],
            },
            VERIFY_REPLY,
        )))
    }
}

const VERIFY_REPLY: u64 = 0;
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(_deps: DepsMut, _: Env, reply: Reply) -> Result<Response, ContractError> {
    match parse_reply_execute_data(reply) {
        Ok(MsgExecuteContractResponse { data: Some(data) }) => {
            // check format of data
            let _: Vec<(String, bool)> = from_binary(&data)?;

            // voting verifier is the only verifier, so just return the response as is
            Ok(Response::new().set_data(data))
        }
        _ => Err(ContractError::Std(StdError::GenericErr {
            msg: "invalid voting verifier reply".to_string(),
        })),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, _msg: QueryMsg) -> StdResult<Binary> {
    todo!()
}
