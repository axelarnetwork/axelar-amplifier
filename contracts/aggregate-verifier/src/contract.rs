#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_binary, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, QueryRequest, Reply, Response,
    StdResult, WasmQuery,
};
use cw_utils::{parse_reply_execute_data, MsgExecuteContractResponse};

use crate::{
    error::ContractError,
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
    state::{Config, CONFIG},
};

use connection_router::msg;
use connection_router::state;

use self::execute::verify_messages;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let verifier = deps.api.addr_validate(&msg.verifier_address)?;
    CONFIG.save(deps.storage, &Config { verifier })?;

    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    match msg {
        ExecuteMsg::VerifyMessages { messages } => {
            // todo: this conversion can go away once the message types are merged
            let msgs = messages
                .into_iter()
                .map(state::Message::try_from)
                .collect::<Result<Vec<state::Message>, _>>()?;

            verify_messages(deps, msgs)
        }
    }
    .map_err(axelar_wasm_std::ContractError::from)
}

pub mod execute {

    use cosmwasm_std::{to_binary, SubMsg, WasmMsg};

    use super::*;

    pub fn verify_messages(
        deps: DepsMut,
        msgs: Vec<state::Message>,
    ) -> Result<Response, ContractError> {
        // Simply pass through to a single verifier for now. If there are multiple verification
        // methods in the future, as well as support for a callback when a message is actually
        // verified, we can store the verification status. But for now, simple pass through works
        let verifier = CONFIG.load(deps.storage)?.verifier;
        Ok(Response::new().add_submessage(SubMsg::reply_on_success(
            WasmMsg::Execute {
                contract_addr: verifier.to_string(),
                msg: to_binary(&ExecuteMsg::VerifyMessages {
                    messages: msgs.into_iter().map(msg::Message::from).collect(),
                })?,
                funds: vec![],
            },
            VERIFY_REPLY,
        )))
    }
}

// not totally necessary, since there is only one possible submessage reply
const VERIFY_REPLY: u64 = 0;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(
    _deps: DepsMut,
    _: Env,
    reply: Reply,
) -> Result<Response, axelar_wasm_std::ContractError> {
    match parse_reply_execute_data(reply) {
        Ok(MsgExecuteContractResponse { data: Some(data) }) => {
            // check format of data
            let _: Vec<(String, bool)> = from_binary(&data)?;

            // only one verifier, so just return the response as is
            Ok(Response::new().set_data(data))
        }
        Ok(MsgExecuteContractResponse { data: None }) => {
            Err(ContractError::InvalidVerifierReply("no data".to_string()))
        }
        Err(e) => Err(ContractError::InvalidVerifierReply(format!(
            "parse error: {}",
            e
        ))),
    }
    .map_err(axelar_wasm_std::ContractError::from)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::IsVerified { messages: _ } => {
            let verifier = CONFIG.load(deps.storage)?.verifier;
            deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: verifier.to_string(),
                msg: to_binary(&msg)?,
            }))
        }
    }
}
