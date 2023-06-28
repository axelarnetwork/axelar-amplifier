use std::collections::HashMap;

use axelar_wasm_std::Snapshot;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, StdError, Storage, Uint256, Uint64};

use crate::{secp256k1::Secp256k1Signature, state::KEY_SETS, ContractError};

#[cw_serde]
pub struct PublicKey(pub HexBinary);

impl From<HexBinary> for PublicKey {
    fn from(other: HexBinary) -> Self {
        Self(other)
    }
}

impl From<PublicKey> for HexBinary {
    fn from(original: PublicKey) -> Self {
        original.0
    }
}

#[cw_serde]
pub struct Message(pub HexBinary);

impl From<HexBinary> for Message {
    fn from(other: HexBinary) -> Self {
        Self(other)
    }
}

impl From<Message> for HexBinary {
    fn from(original: Message) -> Self {
        original.0
    }
}

#[cw_serde]
pub struct Signature(pub HexBinary);

impl From<HexBinary> for Signature {
    fn from(other: HexBinary) -> Self {
        Self(other)
    }
}

impl From<Signature> for HexBinary {
    fn from(original: Signature) -> Self {
        original.0
    }
}

#[cw_serde]
pub struct Key {
    pub id: Uint64,
    pub snapshot: Snapshot,
    pub pub_keys: HashMap<String, PublicKey>,
}

#[cw_serde]
pub enum MultisigState {
    Pending,
    Completed,
}

#[cw_serde]
pub struct SigningSession {
    pub id: Uint64,
    pub key_id: Uint64,
    pub msg: Message,
    pub signatures: HashMap<String, Signature>,
    pub state: MultisigState,
}

impl SigningSession {
    pub fn new(sig_id: Uint64, key_id: Uint64, msg: Message) -> Self {
        Self {
            id: sig_id,
            key_id,
            msg,
            signatures: HashMap::new(),
            state: MultisigState::Pending,
        }
    }

    pub fn add_signature(
        &mut self,
        store: &dyn Storage, // TODO: use mutable and update storage in same function?
        signer: String,
        signature: Signature,
    ) -> Result<(), ContractError> {
        if self.signatures.contains_key(&signer) {
            return Err(ContractError::DuplicateSignature {
                sig_id: self.id,
                signer,
            });
        }

        // TODO: revisit again once expiration and/or rewards are introduced
        if self.state == MultisigState::Completed {
            return Err(ContractError::SigningSessionClosed { sig_id: self.id });
        }

        let key = self.key(store)?;
        if let Some(pub_key) = key.pub_keys.get(&signer) {
            if !signature.verify(&self.msg, pub_key)? {
                return Err(ContractError::InvalidSignature {
                    sig_id: self.id,
                    signer,
                });
            }
        } else {
            return Err(ContractError::NotAParticipant {
                sig_id: self.id,
                signer,
            });
        }

        self.signatures.insert(signer, signature);

        // TODO: may need to also check state != Completed if expiration is ever introduced
        if self.signers_weight(&key) >= key.snapshot.quorum.into() {
            self.state = MultisigState::Completed;
        }

        Ok(())
    }

    pub fn key(&self, store: &dyn Storage) -> Result<Key, StdError> {
        KEY_SETS.load(store, self.key_id.u64())
    }

    fn signers_weight(&self, key: &Key) -> Uint256 {
        self.signatures
            .iter()
            .map(|(addr, _)| -> Uint256 {
                key.snapshot
                    .participants
                    .get(addr)
                    .expect("violated invariant: signature submitted by non-participant")
                    .weight
                    .into()
            })
            .sum()
    }
}
