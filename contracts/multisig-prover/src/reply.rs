use cosmwasm_std::{from_binary, DepsMut, Reply, Response, Uint64};
use cw_utils::{parse_reply_execute_data, MsgExecuteContractResponse};

use crate::state::{COMMANDS_BATCH, CONFIG};
use crate::{
    error::ContractError,
    events::Event,
    state::{MULTISIG_SESSION_BATCH, REPLY_BATCH},
};

pub fn start_multisig_reply(deps: DepsMut, reply: Reply) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    match parse_reply_execute_data(reply) {
        Ok(MsgExecuteContractResponse { data: Some(data) }) => {
            let command_batch_id = REPLY_BATCH.load(deps.storage)?;

            let multisig_session_id: Uint64 =
                from_binary(&data).map_err(|_| ContractError::InvalidContractReply {
                    reason: "invalid multisig session ID".to_string(),
                })?;

            MULTISIG_SESSION_BATCH.save(
                deps.storage,
                multisig_session_id.u64(),
                &command_batch_id,
            )?;

            Ok(Response::new().add_event(
                Event::ProofUnderConstruction {
                    destination_chain: config.chain_name,
                    msg_ids: COMMANDS_BATCH
                        .load(deps.storage, &command_batch_id)?
                        .message_ids,
                    command_batch_id,
                    multisig_session_id,
                }
                .into(),
            ))
        }
        Ok(MsgExecuteContractResponse { data: None }) => Err(ContractError::InvalidContractReply {
            reason: "no data".to_string(),
        }),
        Err(_) => {
            unreachable!("violated invariant: replied failed submessage with ReplyOn::Success")
        }
    }
}
