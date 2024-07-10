use cosmwasm_std::{ensure, OverflowError, OverflowOperation, WasmMsg};
use router_api::ChainName;
use sha3::{Digest, Keccak256};
use signature_verifier_api::client::SignatureVerifier;

use crate::signing::validate_session_signature;
use crate::state::{load_session_signatures, save_pub_key, save_signature};
use crate::verifier_set::VerifierSet;
use crate::{
    key::{KeyTyped, PublicKey, Signature},
    signing::SigningSession,
    state::AUTHORIZED_CALLERS,
};
use error_stack::ResultExt;

use super::*;

pub fn start_signing_session(
    deps: DepsMut,
    env: Env,
    verifier_set_id: String,
    msg: MsgToSign,
    chain_name: ChainName,
    sig_verifier: Option<Addr>,
) -> Result<Response, ContractError> {
    ensure!(
        killswitch::is_contract_active(deps.storage),
        ContractError::SigningDisabled
    );

    let config = CONFIG.load(deps.storage)?;

    let verifier_set = get_verifier_set(deps.storage, &verifier_set_id)?;

    let session_id = SIGNING_SESSION_COUNTER.update(
        deps.storage,
        |mut counter| -> Result<Uint64, ContractError> {
            counter = counter
                .checked_add(Uint64::one())
                .map_err(ContractError::Overflow)?;
            Ok(counter)
        },
    )?;

    let expires_at = env
        .block
        .height
        .checked_add(config.block_expiry.into())
        .ok_or_else(|| {
            OverflowError::new(
                OverflowOperation::Add,
                env.block.height,
                config.block_expiry,
            )
        })?;

    let signing_session = SigningSession::new(
        session_id,
        verifier_set_id.clone(),
        chain_name.clone(),
        msg.clone(),
        expires_at,
        sig_verifier,
    );

    SIGNING_SESSIONS.save(deps.storage, session_id.into(), &signing_session)?;

    let event = Event::SigningStarted {
        session_id,
        verifier_set_id,
        pub_keys: verifier_set.get_pub_keys(),
        msg,
        chain_name,
        expires_at,
    };

    Ok(Response::new()
        .set_data(to_json_binary(&session_id)?)
        .add_event(event.into()))
}

pub fn submit_signature(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    session_id: Uint64,
    signature: HexBinary,
) -> Result<Response, ContractError> {
    ensure!(
        killswitch::is_contract_active(deps.storage),
        ContractError::SigningDisabled
    );

    let config = CONFIG.load(deps.storage)?;
    let mut session = SIGNING_SESSIONS
        .load(deps.storage, session_id.into())
        .map_err(|_| ContractError::SigningSessionNotFound { session_id })?;
    let verifier_set = VERIFIER_SETS.load(deps.storage, &session.verifier_set_id)?;

    let pub_key = match verifier_set.signers.get(&info.sender.to_string()) {
        Some(signer) => Ok(&signer.pub_key),
        None => Err(ContractError::NotAParticipant {
            session_id,
            signer: info.sender.to_string(),
        }),
    }?;

    let signature: Signature = (pub_key.key_type(), signature).try_into()?;

    let sig_verifier = session
        .sig_verifier
        .clone()
        .map(|address| SignatureVerifier {
            address,
            querier: deps.querier,
        });

    validate_session_signature(
        &session,
        &info.sender,
        &signature,
        pub_key,
        env.block.height,
        sig_verifier,
    )?;
    let signature = save_signature(deps.storage, session_id, signature, &info.sender)?;

    let signatures = load_session_signatures(deps.storage, session_id.u64())?;

    let old_state = session.state.clone();

    session.recalculate_session_state(&signatures, &verifier_set, env.block.height);
    SIGNING_SESSIONS.save(deps.storage, session.id.u64(), &session)?;

    let state_changed = old_state != session.state;

    signing_response(
        session,
        state_changed,
        info.sender,
        signature,
        config.rewards_contract.into_string(),
    )
}

pub fn register_verifier_set(
    deps: DepsMut,
    verifier_set: VerifierSet,
) -> Result<Response, ContractError> {
    let verifier_set_id = verifier_set.id();
    VERIFIER_SETS.save(deps.storage, &verifier_set_id, &verifier_set)?;

    Ok(Response::default())
}

pub fn register_pub_key(
    deps: DepsMut,
    info: MessageInfo,
    public_key: PublicKey,
    signed_sender_address: HexBinary,
) -> Result<Response, ContractError> {
    let signed_sender_address: Signature =
        (public_key.key_type(), signed_sender_address).try_into()?;

    let address_hash = Keccak256::digest(info.sender.as_bytes());

    // to prevent anyone from registering a public key that belongs to someone else,
    // we require the sender to sign their own address using the private key
    signed_sender_address
        .verify(address_hash.as_slice(), &public_key)
        .map_err(|_| ContractError::InvalidPublicKeyRegistrationSignature)?;

    save_pub_key(deps.storage, info.sender.clone(), public_key.clone())?;

    Ok(Response::new().add_event(
        Event::PublicKeyRegistered {
            verifier: info.sender,
            public_key,
        }
        .into(),
    ))
}

pub fn require_authorized_caller(
    deps: &DepsMut,
    contract_address: Addr,
) -> error_stack::Result<(), ContractError> {
    AUTHORIZED_CALLERS
        .load(deps.storage, &contract_address)
        .change_context(ContractError::Unauthorized)
}

pub fn authorize_caller(deps: DepsMut, contract_address: Addr) -> Result<Response, ContractError> {
    AUTHORIZED_CALLERS.save(deps.storage, &contract_address, &())?;

    Ok(Response::new().add_event(Event::CallerAuthorized { contract_address }.into()))
}

pub fn unauthorize_caller(
    deps: DepsMut,
    contract_address: Addr,
) -> Result<Response, ContractError> {
    AUTHORIZED_CALLERS.remove(deps.storage, &contract_address);

    Ok(Response::new().add_event(Event::CallerUnauthorized { contract_address }.into()))
}

pub fn enable_signing(deps: DepsMut) -> Result<Response, ContractError> {
    killswitch::disengage(deps.storage, Event::SigningEnabled).map_err(|err| err.into())
}

pub fn disable_signing(deps: DepsMut) -> Result<Response, ContractError> {
    killswitch::engage(deps.storage, Event::SigningDisabled).map_err(|err| err.into())
}

fn signing_response(
    session: SigningSession,
    state_changed: bool,
    signer: Addr,
    signature: Signature,
    rewards_contract: String,
) -> Result<Response, ContractError> {
    let rewards_msg = WasmMsg::Execute {
        contract_addr: rewards_contract,
        msg: to_json_binary(&rewards::msg::ExecuteMsg::RecordParticipation {
            chain_name: session.chain_name,
            event_id: session
                .id
                .to_string()
                .try_into()
                .expect("couldn't convert session_id to nonempty string"),
            verifier_address: signer.to_string(),
        })?,
        funds: vec![],
    };

    let event = Event::SignatureSubmitted {
        session_id: session.id,
        participant: signer,
        signature,
    };

    let mut response = Response::new()
        .add_message(rewards_msg)
        .add_event(event.into());

    if let MultisigState::Completed { completed_at } = session.state {
        if state_changed {
            // only send event if state changed
            response = response.add_event(
                Event::SigningCompleted {
                    session_id: session.id,
                    completed_at,
                }
                .into(),
            )
        }
    }

    Ok(response)
}
