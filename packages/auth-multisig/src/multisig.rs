use std::collections::HashMap;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Binary, Storage, Uint64};
use secp256k1::{verify, Message, PublicKey, Signature};

use crate::{
    state::{Key, KEYS, KEYS_COUNTER},
    AuthError,
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
    key_id: Uint64,
    payload_hash: [u8; 32],
    sigs: HashMap<String, WorkerSignature>, // TODO: move out to cosmwasm Map?
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
    pub expires_at: Uint64,
    pub completed_at: Option<Uint64>,
    pub grace_period: Uint64,
    pub metadata: Binary,
}

impl SigningSession {
    pub fn new(
        id: Uint64,
        key: &Key,
        payload_hash: [u8; 32],
        expires_at: Uint64,
        grace_period: Uint64,
        metadata: Binary,
    ) -> Self {
        Self {
            id,
            multisig: MultiSig {
                key_id: key.id,
                payload_hash,
                sigs: HashMap::new(),
            },
            state: MultisigState::Pending,
            key: key.clone(),
            expires_at,
            completed_at: None,
            grace_period,
            metadata,
        }
    }

    pub fn is_expired(&self, block_height: u64) -> bool {
        block_height >= self.expires_at.u64()
    }

    pub fn add_signature(
        &mut self,
        block_height: u64,
        signer: Addr,
        signature: WorkerSignature,
    ) -> Result<(), AuthError> {
        if self.is_expired(block_height) {
            return Err(AuthError::ExpiredSigningSession { id: self.id });
        }

        if self
            .multisig
            .sigs
            .contains_key(&signer.clone().into_string())
        {
            return Err(AuthError::AlreadySigned {
                signer,
                id: self.id,
            });
        }

        if let Some(pub_key) = self.key.pub_keys.get(&signer.clone().into_string()) {
            if !signature.verify(self.multisig.payload_hash, pub_key) {
                return Err(AuthError::AlreadySigned {
                    signer,
                    id: self.id,
                });
            }
        } else {
            return Err(AuthError::NotEligibleToSign {
                signer,
                id: self.id,
            });
        }

        if self.state == MultisigState::Completed && !self.is_within_grace_period(block_height) {
            return Err(AuthError::SigningSessionClosed { id: self.id });
        }

        self.multisig.sigs.insert(signer.into_string(), signature);

        if self.state != MultisigState::Completed
            && self.key.snapshot.get_participants_weight()
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

pub fn get_current_key_id(store: &mut dyn Storage) -> Result<Uint64, AuthError> {
    let counter = KEYS_COUNTER.load(store)?;
    let key_option = KEYS.may_load(store, counter)?;

    if let Some(key) = key_option {
        return Ok(key.id);
    } else {
    }

    Err(AuthError::NotActiveKey {})
}
