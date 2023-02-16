use std::ops::Add;

use cosmwasm_std::{Event, Storage, Uint64};
use serde_json::to_string;

use crate::{
    state::{
        KeyState, SigningSession, KEYS, SERVICE_INFO, SIGNING_SESSIONS, SIGNING_SESSION_COUNTER,
    },
    ContractError,
};

pub fn get_current_key_id() -> String {
    todo!()
}

pub fn sign(
    store: &mut dyn Storage,
    block_height: u64,
    key_id: String,
    payload_hash: [u8; 32],
    chain_name: String,
    command_batch_id: [u8; 32],
) -> Result<Event, ContractError> {
    let key = KEYS
        .load(store, &key_id)
        .map_err(|_| ContractError::KeyNotFound {
            key: key_id.clone(),
        })?;

    if key.state != KeyState::Active {
        return Err(ContractError::KeyNotActive { key: key_id });
    }

    let service = SERVICE_INFO.load(store)?;

    let expires_at = service.signing_timeout.add(Uint64::from(block_height));
    let sig_session_id =
        SIGNING_SESSION_COUNTER.update(store, |mut counter| -> Result<u64, ContractError> {
            counter += 1;
            Ok(counter)
        })?;
    let signing_session = SigningSession::new(
        Uint64::from(sig_session_id),
        &key,
        chain_name,
        command_batch_id,
        payload_hash,
        expires_at,
        service.signing_grace_period,
    );
    SIGNING_SESSIONS.save(store, sig_session_id, &signing_session)?;

    let event = Event::new("SigningStarted")
        .add_attribute("sig_id", Uint64::from(sig_session_id))
        .add_attribute("key_id", key_id)
        .add_attribute("pub_keys", to_string(&key.pub_keys).unwrap())
        .add_attribute("payload_hash", hex::encode(payload_hash));

    Ok(event)
}
