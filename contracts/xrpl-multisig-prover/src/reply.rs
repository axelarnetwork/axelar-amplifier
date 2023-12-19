use cosmwasm_std::{from_binary, DepsMut, Reply, Response, Uint64};
use cw_utils::{parse_reply_execute_data, MsgExecuteContractResponse};

use crate::{
    error::ContractError,
    events::Event,
    state::{MULTISIG_SESSION_TX, REPLY_TX_HASH},
};

pub fn start_multisig_reply(deps: DepsMut, reply: Reply) -> Result<Response, ContractError> {
    match parse_reply_execute_data(reply) {
        Ok(MsgExecuteContractResponse { data: Some(data) }) => {
            let tx_hash = REPLY_TX_HASH.load(deps.storage)?;

            let multisig_session_id: Uint64 =
                from_binary(&data).map_err(|_| ContractError::InvalidContractReply {
                    reason: "invalid multisig session ID".to_string(),
                })?;

            MULTISIG_SESSION_TX.save(
                deps.storage,
                multisig_session_id.u64(),
                &tx_hash,
            )?;

            Ok(Response::new().add_event(
                Event::ProofUnderConstruction {
                    tx_hash,
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
