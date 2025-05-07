use cosmwasm_std::{from_json, DepsMut, Reply, Response, Uint64};
use cw_utils::{parse_execute_response_data, MsgExecuteContractResponse, ParseReplyError};
use multisig_prover_api::error::ContractError;

use crate::events::Event;
use crate::state::{CONFIG, MULTISIG_SESSION_PAYLOAD, PAYLOAD, REPLY_TRACKER};

pub fn start_multisig_reply(deps: DepsMut, reply: Reply) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    #[allow(deprecated)]
    // TODO: use `msg_responses` instead when the cosmwasm vm is updated to 2.x.x
    let data = reply
        .result
        .into_result()
        .map_err(ParseReplyError::SubMsgFailure)?
        .data
        .ok_or_else(|| ParseReplyError::ParseFailure("missing reply data".to_owned()))?;

    match parse_execute_response_data(data.as_slice()) {
        Ok(MsgExecuteContractResponse { data: Some(data) }) => {
            let payload_id = REPLY_TRACKER.load(deps.storage)?;

            let multisig_session_id: Uint64 =
                from_json(data).map_err(|_| ContractError::InvalidContractReply {
                    reason: "invalid multisig session ID".to_string(),
                })?;

            MULTISIG_SESSION_PAYLOAD.save(deps.storage, multisig_session_id.u64(), &payload_id)?;

            let msg_ids = PAYLOAD
                .load(deps.storage, &payload_id)?
                .message_ids()
                .unwrap_or_default();

            Ok(Response::new().add_event(Event::ProofUnderConstruction {
                destination_chain: config.chain_name,
                msg_ids,
                payload_id,
                multisig_session_id,
            }))
        }
        Ok(MsgExecuteContractResponse { data: None }) => Err(ContractError::InvalidContractReply {
            reason: "no data".to_string(),
        }),
        Err(_) => {
            unreachable!("violated invariant: replied failed submessage with ReplyOn::Success")
        }
    }
}
