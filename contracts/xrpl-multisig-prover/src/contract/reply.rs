use cosmwasm_std::{from_json, DepsMut, HexBinary, Reply, Response, Uint64};
use cw_utils::{parse_reply_execute_data, MsgExecuteContractResponse};

use crate::error::ContractError;
use crate::events::Event;
use crate::xrpl_serialize::XRPLSerialize;
use crate::state::{
    CONFIG, MultisigSession, CROSS_CHAIN_ID_TO_MULTISIG_SESSION, MULTISIG_SESSION_ID_TO_UNSIGNED_TX_HASH, REPLY_CROSS_CHAIN_ID, REPLY_UNSIGNED_TX_HASH, UNSIGNED_TX_HASH_TO_TX_INFO
};

pub fn start_multisig_reply(deps: DepsMut, reply: Reply) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    match parse_reply_execute_data(reply.clone()) {
        Ok(MsgExecuteContractResponse { data: Some(data) }) => {
            let multisig_session_id: Uint64 = from_json(data)
                .map_err(|_| ContractError::InvalidContractReply {
                    reason: "invalid multisig session ID".to_string(),
                })?;

            let unsigned_tx_hash = REPLY_UNSIGNED_TX_HASH.load(deps.storage)?;
            MULTISIG_SESSION_ID_TO_UNSIGNED_TX_HASH.save(
                deps.storage,
                multisig_session_id.u64(),
                &unsigned_tx_hash,
            )?;

            let tx_info = UNSIGNED_TX_HASH_TO_TX_INFO.load(deps.storage, &unsigned_tx_hash)?;

            let signing_started_attributes: Vec<_> = reply
                .result
                .into_result()
                .map_err(|e| ContractError::FailedToStartMultisigSession {
                    reason: e,
                })?
                .events
                .into_iter()
                .filter(|e| e.ty == "wasm-signing_started")
                .flat_map(|e| e.attributes)
                .collect();

            let expires_at = signing_started_attributes
                .clone()
                .into_iter()
                .filter(|a| a.key.eq("expires_at"))
                .next()
                .expect("violated invariant: wasm-signing_started event missing expires_at")
                .value
                .parse()
                .expect("violated invariant: expires_at is not a number");

            match REPLY_CROSS_CHAIN_ID.may_load(deps.storage)? {
                Some(cc_id) => {
                    CROSS_CHAIN_ID_TO_MULTISIG_SESSION.save(
                        deps.storage,
                        &cc_id,
                        &MultisigSession {
                            id: multisig_session_id.u64(),
                            expires_at,
                        },
                    )?;
                    REPLY_CROSS_CHAIN_ID.remove(deps.storage);
                }
                None => (),
            }

            REPLY_UNSIGNED_TX_HASH.remove(deps.storage);

            Ok(Response::new()
                .add_event(
                    Event::ProofUnderConstruction {
                        destination_chain: config.chain_name,
                        unsigned_tx_hash,
                        multisig_session_id,
                    }
                    .into(),
                )
                .add_event(
                    cosmwasm_std::Event::new("xrpl_signing_started")
                        .add_attributes(
                            signing_started_attributes
                                .into_iter()
                                .filter(|a| !a.key.starts_with('_') && a.key != "msg")
                                .collect::<Vec<_>>()
                        )
                        .add_attribute(
                            "unsigned_tx",
                            HexBinary::from(tx_info.unsigned_tx.xrpl_serialize()?).to_hex(),
                        )
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
