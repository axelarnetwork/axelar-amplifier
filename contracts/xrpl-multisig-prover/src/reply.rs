use cosmwasm_std::{from_binary, Attribute, DepsMut, HexBinary, Reply, Response, Uint64};
use cw_utils::{parse_reply_execute_data, MsgExecuteContractResponse};

use crate::{
    error::ContractError, events::Event, state::{MESSAGE_ID_TO_MULTISIG_SESSION_ID, MULTISIG_SESSION_TX, REPLY_MESSAGE_ID, REPLY_TX_HASH, TRANSACTION_INFO}, xrpl_multisig::XRPLSerialize
};

pub fn start_multisig_reply(deps: DepsMut, reply: Reply) -> Result<Response, ContractError> {
    match parse_reply_execute_data(reply.clone()) {
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

            match REPLY_MESSAGE_ID.may_load(deps.storage)? {
                Some(message_id) => {
                    MESSAGE_ID_TO_MULTISIG_SESSION_ID.save(
                        deps.storage,
                        &message_id,
                        &multisig_session_id.u64(),
                    )?
                },
                None => (),
            }

            REPLY_MESSAGE_ID.remove(deps.storage);

            let tx_info = TRANSACTION_INFO.load(deps.storage, &tx_hash)?;

            let res = reply.result.unwrap();

            let evt_attributes: Vec<Attribute> = res.events
                .into_iter()
                .filter(|e| e.ty == "wasm-signing_started")
                .map(|e| e.attributes)
                .flatten()
                .filter(|a| !a.key.starts_with("_") && a.key != "msg")
                .collect();

            let evt = cosmwasm_std::Event::new("xrpl_signing_started")
                .add_attributes(evt_attributes)
                .add_attribute("unsigned_tx", HexBinary::from(tx_info.unsigned_contents.xrpl_serialize()?).to_hex());

            Ok(Response::new().add_event(
                Event::ProofUnderConstruction {
                    tx_hash,
                    multisig_session_id,
                }
                .into(),
            ).add_event(evt))
        }
        Ok(MsgExecuteContractResponse { data: None }) => Err(ContractError::InvalidContractReply {
            reason: "no data".to_string(),
        }),
        Err(_) => {
            unreachable!("violated invariant: replied failed submessage with ReplyOn::Success")
        }
    }
}
