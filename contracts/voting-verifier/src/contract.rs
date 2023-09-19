#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};

use connection_router::state;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{Config, CONFIG, CONFIRMED_WORKER_SETS};
use crate::{execute, query};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let config = Config {
        service_name: msg.service_name,
        service_registry: deps.api.addr_validate(&msg.service_registry_address)?,
        source_gateway_address: msg.source_gateway_address,
        voting_threshold: msg.voting_threshold,
        block_expiry: msg.block_expiry,
        confirmation_height: msg.confirmation_height,
        source_chain: msg.source_chain,
    };
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new().add_event(config.into()))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    match msg {
        ExecuteMsg::VerifyMessages { messages } => {
            if messages.is_empty() {
                Err(ContractError::EmptyMessages)?;
            }

            // todo: extract to conversion function
            let messages = messages
                .into_iter()
                .map(state::Message::try_from)
                .collect::<Result<Vec<state::Message>, _>>()?;

            let source_chain = CONFIG.load(deps.storage)?.source_chain;

            if messages
                .iter()
                .any(|message| !message.source_chain.eq(&source_chain))
            {
                Err(ContractError::SourceChainMismatch(source_chain))?;
            }

            execute::verify_messages(deps, env, messages)
        }
        ExecuteMsg::Vote { poll_id, votes } => execute::vote(deps, env, info, poll_id, votes),
        ExecuteMsg::EndPoll { poll_id } => execute::end_poll(deps, env, poll_id),
        ExecuteMsg::ConfirmWorkerSet {
            message_id,
            new_operators,
        } => execute::confirm_worker_set(deps, env, message_id, new_operators),
    }
    .map_err(axelar_wasm_std::ContractError::from)
}
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::IsVerified { messages } => {
            let messages = messages
                .into_iter()
                .map(state::Message::try_from)
                .collect::<Result<Vec<_>, _>>()?;

            to_binary(&query::verification_statuses(deps, messages)?)
        }

        QueryMsg::GetPoll { poll_id: _ } => {
            todo!()
        }
        QueryMsg::IsWorkerSetConfirmed { new_operators } => to_binary(
            &CONFIRMED_WORKER_SETS
                .may_load(deps.storage, new_operators.hash())?
                .is_some(),
        ),
    }
}
