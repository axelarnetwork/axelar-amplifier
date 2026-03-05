//! Module for handling feature flag differences

use chain_codec_api::msg::FullMessagePayloads;
use chain_codec_api::{Payload, VerifierSet};
use cosmwasm_std::{Deps, DepsMut, HexBinary, Uint64};
use error_stack::{report, ResultExt};
use multisig_prover_api::payload::PayloadId;
use router_api::Message;
use sha3::{Digest, Keccak256};

use crate::error::ContractError;
use crate::state::{Config, FULL_MESSAGE_PAYLOADS};

pub fn query_payload_digest(
    deps: Deps,
    config: &Config,
    verifier_set: VerifierSet,
    payload: Payload,
    full_message_payloads: FullMessagePayloads,
) -> error_stack::Result<HexBinary, ContractError> {
    let chain_codec: chain_codec_api::Client =
        client::ContractClient::new(deps.querier, &config.chain_codec).into();

    chain_codec
        .payload_digest(
            config.domain_separator,
            verifier_set,
            payload,
            full_message_payloads,
        )
        .change_context(ContractError::FailedToQueryChainCodec)
}

pub fn check_and_store_full_payloads(
    deps: DepsMut,
    config: &Config,
    payload_id: PayloadId,
    full_message_payloads: &Vec<HexBinary>,
    messages: Vec<Message>,
) -> error_stack::Result<(), ContractError> {
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

    // only save this if we actually need it later
    if config.notify_signing_session {
        FULL_MESSAGE_PAYLOADS
            .save(deps.storage, &payload_id, full_message_payloads)
            .map_err(ContractError::from)?;
    }

    Ok(())
}

/// Adds a `NotifySigningSession` message to the response (notifies the chain codec).
pub fn notify_signing_session(
    deps: DepsMut,
    config: &Config,
    response: cosmwasm_std::Response,
    payload_id: &PayloadId,
    payload: Payload,
    multisig_session_id: Uint64,
) -> Result<cosmwasm_std::Response, ContractError> {
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
        match crate::state::FULL_MESSAGE_PAYLOADS.may_load(deps.storage, payload_id)? {
            Some(payloads) => FullMessagePayloads::Payloads(payloads),
            None => FullMessagePayloads::VerifierSetUpdate,
        };

    let response = response.add_message(chain_codec.notify_signing_session(
        config.domain_separator,
        multisig_session_id,
        verifier_set,
        payload,
        full_message_payloads,
    ));

    Ok(response)
}
