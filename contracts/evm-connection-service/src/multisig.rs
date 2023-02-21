use std::{collections::BTreeMap, ops::Add};

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Binary, Event, Storage, Uint64};
use secp256k1::{verify, Message, PublicKey, Signature};
use serde_json::to_string;

use crate::{
    state::{Key, KeyState, KEYS, SERVICE_INFO, SIGNING_SESSIONS, SIGNING_SESSION_COUNTER},
    ContractError,
};

#[cw_serde]
pub struct WorkerSignature(pub Binary);
impl WorkerSignature {
    // TODO: test verification
    pub fn verify(&self, payload_hash: [u8; 32], public_key: &Binary) -> bool {
        let message = Message::parse(&payload_hash);
        let pubkey = PublicKey::parse_slice(public_key, None).unwrap();
        let signature = Signature::parse_der(&self.0).unwrap();

        verify(&message, &signature, &pubkey)
    }
}

#[cw_serde]
pub struct MultiSig {
    key_id: String,
    payload_hash: [u8; 32],
    sigs: BTreeMap<Addr, WorkerSignature>, // TODO: move out to cosmwasm Map?
}

#[cw_serde]
pub enum MultisigState {
    Pending,
    Completed,
}

#[cw_serde]
pub struct SigningSession {
    pub id: Uint64,
    pub multisig: MultiSig,
    pub state: MultisigState,
    pub key: Key,
    pub chain_name: String,
    pub command_batch_id: [u8; 32],
    pub expires_at: Uint64,
    pub completed_at: Option<Uint64>,
    pub grace_period: Uint64,
}

impl SigningSession {
    pub fn new(
        id: Uint64,
        key: &Key,
        chain_name: String,
        command_batch_id: [u8; 32],
        payload_hash: [u8; 32],
        expires_at: Uint64,
        grace_period: Uint64,
    ) -> Self {
        Self {
            id,
            multisig: MultiSig {
                key_id: key.id.clone(),
                payload_hash,
                sigs: BTreeMap::new(),
            },
            state: MultisigState::Pending,
            key: key.clone(),
            chain_name,
            command_batch_id,
            expires_at,
            completed_at: None,
            grace_period,
        }
    }

    pub fn is_expired(&self, block_height: u64) -> bool {
        block_height >= self.expires_at.u64()
    }

    pub fn add_signature(
        &mut self,
        store: &mut dyn Storage,
        block_height: u64,
        signer: Addr,
        signature: WorkerSignature,
    ) -> Result<(), ContractError> {
        if self.is_expired(block_height) {
            return Err(ContractError::ExpiredSigningSession { id: self.id });
        }

        if !self.key.pub_keys.contains_key(&signer) {
            return Err(ContractError::InvalidParticipant {
                signer,
                id: self.id,
            });
        }

        if self.multisig.sigs.contains_key(&signer) {
            return Err(ContractError::AlreadySigned {
                signer,
                id: self.id,
            });
        }

        let public_key = self.key.pub_keys.get(&signer).unwrap();
        if !signature.verify(self.multisig.payload_hash, public_key) {
            return Err(ContractError::AlreadySigned {
                signer,
                id: self.id,
            });
        }

        if self.state == MultisigState::Completed && !self.is_within_grace_period(block_height) {
            return Err(ContractError::SigningSessionClosed { id: self.id });
        }

        self.multisig.sigs.insert(signer, signature);

        if self.state != MultisigState::Completed
            && self.key.snapshot.get_participants_weight(store)
                >= self
                    .key
                    .snapshot
                    .calculate_min_passing_weight(&self.key.signing_treshhold)
        {
            self.completed_at = Some(Uint64::from(block_height));
            self.state = MultisigState::Completed;
        }

        Ok(())
    }

    pub fn is_within_grace_period(&self, block_height: u64) -> bool {
        block_height <= self.completed_at.unwrap().u64() + self.grace_period.u64()
    }
}

pub fn get_current_key_id() -> String {
    todo!()
}

pub fn start_signing_session(
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
