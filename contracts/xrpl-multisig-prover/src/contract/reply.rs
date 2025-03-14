use cosmwasm_std::{from_json, DepsMut, HexBinary, Reply, Response, Uint64};
use cw_utils::{parse_execute_response_data, MsgExecuteContractResponse, ParseReplyError};
use xrpl_types::types::XRPLUnsignedTxToSign;

use crate::error::ContractError;
use crate::events::Event;
use crate::state::{
    MultisigSession, CONFIG, CROSS_CHAIN_ID_TO_MULTISIG_SESSION,
    MULTISIG_SESSION_ID_TO_UNSIGNED_TX_HASH, REPLY_CROSS_CHAIN_ID, REPLY_UNSIGNED_TX_HASH,
    UNSIGNED_TX_HASH_TO_TX_INFO,
};
use crate::xrpl_serialize::XRPLSerialize;

pub fn start_multisig_reply(deps: DepsMut, reply: Reply) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    #[allow(deprecated)]
    // TODO: use `msg_responses` instead when the cosmwasm vm is updated to 2.x.x
    let data = reply
        .result
        .clone()
        .into_result()
        .map_err(ParseReplyError::SubMsgFailure)?
        .data
        .ok_or_else(|| ParseReplyError::ParseFailure("missing reply data".to_owned()))?;

    match parse_execute_response_data(data.as_slice()) {
        Ok(MsgExecuteContractResponse { data: Some(data) }) => {
            let multisig_session_id: Uint64 =
                from_json(data).map_err(|_| ContractError::InvalidContractReply {
                    reason: "invalid multisig session ID".to_string(),
                })?;

            let unsigned_tx_hash = REPLY_UNSIGNED_TX_HASH.load(deps.storage)?;
            MULTISIG_SESSION_ID_TO_UNSIGNED_TX_HASH.save(
                deps.storage,
                multisig_session_id.u64(),
                &unsigned_tx_hash.tx_hash,
            )?;

            let tx_info =
                UNSIGNED_TX_HASH_TO_TX_INFO.load(deps.storage, &unsigned_tx_hash.tx_hash)?;

            let signing_started_attributes: Vec<_> = reply
                .result
                .into_result()
                .map_err(|e| ContractError::FailedToStartMultisigSession { reason: e })?
                .events
                .into_iter()
                .filter(|e| e.ty == "wasm-signing_started")
                .flat_map(|e| e.attributes)
                .collect();

            let expires_at = signing_started_attributes
                .clone()
                .into_iter()
                .find(|a| a.key.eq("expires_at"))
                .expect("violated invariant: wasm-signing_started event missing expires_at")
                .value
                .parse()
                .expect("violated invariant: expires_at is not a number");

            let opt_cc_id = REPLY_CROSS_CHAIN_ID.may_load(deps.storage)?;
            if let Some(cc_id) = &opt_cc_id {
                CROSS_CHAIN_ID_TO_MULTISIG_SESSION.save(
                    deps.storage,
                    cc_id,
                    &MultisigSession {
                        id: multisig_session_id.u64(),
                        expires_at,
                    },
                )?;
                REPLY_CROSS_CHAIN_ID.remove(deps.storage);
            };

            REPLY_UNSIGNED_TX_HASH.remove(deps.storage);

            Ok(Response::new()
                .add_event(Event::ProofUnderConstruction {
                    destination_chain: config.chain_name,
                    unsigned_tx_hash: unsigned_tx_hash.clone(),
                    multisig_session_id,
                    msg_ids: opt_cc_id.clone().map(|cc_id| vec![cc_id]),
                })
                .add_event(
                    cosmwasm_std::Event::new("xrpl_signing_started")
                        .add_attributes(
                            signing_started_attributes
                                .into_iter()
                                .filter(|a| !a.key.starts_with('_') && a.key != "msg")
                                .collect::<Vec<_>>(),
                        )
                        .add_attribute(
                            "unsigned_tx",
                            HexBinary::from(
                                XRPLUnsignedTxToSign {
                                    unsigned_tx: tx_info.unsigned_tx,
                                    unsigned_tx_hash,
                                    cc_id: opt_cc_id,
                                }
                                .xrpl_serialize()?,
                            )
                            .to_hex(),
                        ),
                ))
        }
        Ok(MsgExecuteContractResponse { data: None }) => Err(ContractError::InvalidContractReply {
            reason: "no data".to_string(),
        }),
        Err(e) => {
            unreachable!(
                "violated invariant: replied failed submessage with ReplyOn::Success: {:?}",
                e
            )
        }
    }
}
