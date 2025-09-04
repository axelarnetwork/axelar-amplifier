//! Module for handling feature flag differences

use chain_codec_api::{Payload, VerifierSet};
use cosmwasm_std::{Deps, DepsMut, HexBinary, Uint64};
use error_stack::ResultExt;
use multisig_prover_api::payload::PayloadId;
use router_api::Message;

use crate::error::ContractError;
use crate::state::{Config, FULL_MESSAGE_PAYLOADS};

pub fn query_payload_digest(
    deps: Deps,
    config: &Config,
    verifier_set: VerifierSet,
    payload: Payload,
    full_message_payloads: Vec<HexBinary>,
) -> error_stack::Result<HexBinary, ContractError> {
    let chain_codec: chain_codec_api::Client =
        client::ContractClient::new(deps.querier, &config.chain_codec).into();

    #[cfg(feature = "receive-payload")]
    {
        chain_codec
            .payload_digest(verifier_set, payload, full_message_payloads)
            .change_context(ContractError::FailedToQueryChainCodec)
    }
    #[cfg(not(feature = "receive-payload"))]
    {
        let _ = full_message_payloads;

        chain_codec
            .payload_digest(verifier_set, payload)
            .change_context(ContractError::FailedToQueryChainCodec)
    }
}

pub fn receive_full_payloads(
    deps: DepsMut,
    payload_id: PayloadId,
    full_message_payloads: &Vec<HexBinary>,
    messages: Vec<Message>,
) -> error_stack::Result<(), ContractError> {
    #[cfg(feature = "receive-payload")]
    {
        use error_stack::report;
        use sha3::{Digest, Keccak256};

        if messages.len() != full_message_payloads.len() {
            return Err(report!(ContractError::PayloadBytesMismatch {
                full_message_payloads: full_message_payloads.len(),
                messages: messages.len(),
            }));
        }

        for (message, message_payload) in messages.into_iter().zip(full_message_payloads) {
            let payload_hash: [u8; 32] = Keccak256::digest(message_payload).into();
            if message.payload_hash != payload_hash {
                return Err(report!(ContractError::PayloadHashMismatch {
                    message_id: message.cc_id,
                    expected: message.payload_hash,
                    actual: payload_hash,
                }));
            }
        }
    }

    #[cfg(not(feature = "receive-payload"))]
    let _ = messages;

    FULL_MESSAGE_PAYLOADS.save(deps.storage, &payload_id, full_message_payloads)?;

    Ok(())
}

/// Adds a `NotifySigningSession` message to the response if the `notify-signing-session` feature is enabled.
pub fn notify_signing_session(
    deps: DepsMut,
    config: &Config,
    #[allow(unused_mut)] mut response: cosmwasm_std::Response,
    payload_id: &PayloadId,
    payload: Payload,
    multisig_session_id: Uint64,
) -> Result<cosmwasm_std::Response, ContractError> {
    #[cfg(feature = "notify-signing-session")]
    {
        let verifier_set = crate::state::CURRENT_VERIFIER_SET
            .may_load(deps.storage)
            .map_err(ContractError::from)?
            .ok_or(ContractError::NoVerifierSet)?;

        let chain_codec: chain_codec_api::Client =
            client::ContractClient::new(deps.querier, &config.chain_codec).into();

        // full message payloads are only stored during proof construction.
        // if this is a reply to a verifier set update, there are no full message payloads,
        // so we use `may_load` and pass an empty vec in that case
        let full_message_payloads =
            crate::state::FULL_MESSAGE_PAYLOADS.may_load(deps.storage, payload_id)?;

        response = response.add_message(notify_msg(
            &chain_codec,
            multisig_session_id,
            verifier_set,
            payload,
            full_message_payloads.unwrap_or_default(),
        ));
    }
    #[cfg(not(feature = "notify-signing-session"))]
    let _ = (deps, config, payload_id, payload, multisig_session_id);

    Ok(response)
}

#[cfg(feature = "notify-signing-session")]
fn notify_msg(
    chain_codec: &chain_codec_api::Client,
    multisig_session_id: Uint64,
    verifier_set: VerifierSet,
    payload: Payload,
    full_message_payloads: Vec<HexBinary>,
) -> cosmwasm_std::CosmosMsg {
    #[cfg(feature = "receive-payload")]
    {
        chain_codec.notify_signing_session(
            multisig_session_id,
            verifier_set,
            payload,
            full_message_payloads,
        )
    }
    #[cfg(not(feature = "receive-payload"))]
    {
        let _ = full_message_payloads;
        chain_codec.notify_signing_session(multisig_session_id, verifier_set, payload)
    }
}
