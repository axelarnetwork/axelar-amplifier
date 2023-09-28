use std::collections::HashMap;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Uint256, Uint64};

use axelar_wasm_std::Snapshot;

use crate::{
    key::Signature,
    types::{Key, KeyID, MsgToSign, MultisigState},
    ContractError,
};

#[cw_serde]
pub struct SigningSession {
    pub id: Uint64,
    pub key_id: KeyID,
    pub msg: MsgToSign,
    pub signatures: HashMap<String, Signature>,
    pub state: MultisigState,
}

impl SigningSession {
    pub fn new(session_id: Uint64, key_id: KeyID, msg: MsgToSign) -> Self {
        Self {
            id: session_id,
            key_id,
            msg,
            signatures: HashMap::new(),
            state: MultisigState::Pending,
        }
    }

    pub fn add_signature(
        &mut self,
        key: Key,
        signer: String,
        signature: Signature,
    ) -> Result<(), ContractError> {
        assert!(self.key_id == key.id, "violated invariant: key_id mismatch"); // TODO: correct way of handling this?

        if self.signatures.contains_key(&signer) {
            return Err(ContractError::DuplicateSignature {
                session_id: self.id,
                signer,
            });
        }

        // TODO: revisit again once expiration and/or rewards are introduced
        if self.state == MultisigState::Completed {
            return Err(ContractError::SigningSessionClosed {
                session_id: self.id,
            });
        }

        match key.pub_keys.get(&signer) {
            Some(pub_key) if !signature.verify(&self.msg, pub_key)? => {
                return Err(ContractError::InvalidSignature {
                    session_id: self.id,
                    signer,
                });
            }
            None => {
                return Err(ContractError::NotAParticipant {
                    session_id: self.id,
                    signer,
                });
            }
            _ => {}
        }

        self.signatures.insert(signer, signature);

        // TODO: may need to also check state != Completed if expiration is ever introduced
        if self.signers_weight(&key.snapshot) >= key.snapshot.quorum.into() {
            self.state = MultisigState::Completed;
        }

        Ok(())
    }

    fn signers_weight(&self, snapshot: &Snapshot) -> Uint256 {
        self.signatures
            .keys()
            .map(|addr| -> Uint256 {
                snapshot
                    .participants
                    .get(addr)
                    .expect("violated invariant: signature submitted by non-participant")
                    .weight
                    .into()
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::{testing::MockStorage, Addr, HexBinary};

    use crate::{
        key::KeyType,
        state::{KEYS, SIGNING_SESSIONS},
        test::common::{build_key, build_snapshot, TestSigner},
        test::common::{ecdsa_test_data, ed25519_test_data},
    };

    use super::*;

    pub struct TestConfig {
        pub store: MockStorage,
        pub key_id: KeyID,
        pub message: MsgToSign,
        pub signers: Vec<TestSigner>,
        pub key_type: KeyType,
    }

    fn ecdsa_setup() -> TestConfig {
        let mut store = MockStorage::new();

        let signers = ecdsa_test_data::signers();
        let snapshot = build_snapshot(&signers);

        let key_id = KeyID {
            owner: Addr::unchecked("owner"),
            subkey: "subkey".to_string(),
        };
        let key = build_key(KeyType::Ecdsa, key_id, &signers, snapshot);
        KEYS.save(&mut store, (&key.id).into(), &key).unwrap();

        let message: MsgToSign = ecdsa_test_data::message().try_into().unwrap();

        TestConfig {
            store,
            key_id: key.id,
            message,
            signers,
            key_type: KeyType::Ecdsa,
        }
    }

    fn ed25519_setup() -> TestConfig {
        let mut store = MockStorage::new();

        let signers = ed25519_test_data::signers();
        let snapshot = build_snapshot(&signers);

        let key_id = KeyID {
            owner: Addr::unchecked("owner"),
            subkey: "subkey".to_string(),
        };
        let key = build_key(KeyType::Ed25519, key_id, &signers, snapshot);
        KEYS.save(&mut store, (&key.id).into(), &key).unwrap();

        let message: MsgToSign = ed25519_test_data::message().try_into().unwrap();

        TestConfig {
            store,
            key_id: key.id,
            message,
            signers,
            key_type: KeyType::Ed25519,
        }
    }

    fn sign(
        session: &mut SigningSession,
        signer_ix: usize,
        config: &mut TestConfig,
    ) -> Result<(), ContractError> {
        let signer = config.signers[signer_ix].clone();

        let key = KEYS.load(&config.store, (&session.key_id).into())?;

        let res = session.add_signature(
            key,
            signer.address.clone().into_string(),
            Signature::try_from((config.key_type, signer.signature.clone())).unwrap(),
        );

        SIGNING_SESSIONS.save(&mut config.store, session.id.u64(), &session)?;

        res
    }

    #[test]
    fn test_add_signature() {
        for mut config in [ecdsa_setup(), ed25519_setup()] {
            let mut session =
                SigningSession::new(Uint64::one(), config.key_id.clone(), config.message.clone());

            let result = sign(&mut session, 0, &mut config);
            let stored = SIGNING_SESSIONS
                .load(&config.store, session.id.u64())
                .unwrap();
            assert!(result.is_ok());
            assert_eq!(session.signatures.len(), 1);
            assert_eq!(session.state, MultisigState::Pending);
            assert_eq!(stored, session);

            let result = sign(&mut session, 0, &mut config);
            let stored = SIGNING_SESSIONS
                .load(&config.store, session.id.u64())
                .unwrap();
            assert_eq!(
                result.unwrap_err(),
                ContractError::DuplicateSignature {
                    session_id: session.id,
                    signer: config.signers[0].address.clone().into_string()
                }
            );
            assert_eq!(session.signatures.len(), 1);
            assert_eq!(session.state, MultisigState::Pending);
            assert_eq!(stored, session);

            let result = sign(&mut session, 1, &mut config);
            let stored = SIGNING_SESSIONS
                .load(&config.store, session.id.u64())
                .unwrap();
            assert!(result.is_ok());
            assert_eq!(session.signatures.len(), 2);
            assert_eq!(session.state, MultisigState::Completed);
            assert_eq!(stored, session);

            let result = sign(&mut session, 2, &mut config);
            let stored = SIGNING_SESSIONS
                .load(&config.store, session.id.u64())
                .unwrap();
            assert_eq!(
                result.unwrap_err(),
                ContractError::SigningSessionClosed {
                    session_id: session.id
                }
            );
            assert_eq!(session.signatures.len(), 2);
            assert_eq!(session.state, MultisigState::Completed);
            assert_eq!(stored, session);
        }
    }

    #[test]
    fn test_add_invalid_signature() {
        for config in [ecdsa_setup(), ed25519_setup()] {
            let mut session =
                SigningSession::new(Uint64::one(), config.key_id.clone(), config.message.clone());

            let sig_bytes = match config.key_type {
                KeyType::Ecdsa =>   "a58c9543b9df54578ec45838948e19afb1c6e4c86b34d9899b10b44e619ea74e19b457611e41a047030ed233af437d7ecff84de97cb6b3c13d73d22874e03511",
                KeyType::Ed25519 => "1fe264eb7258d48d8feedea4d237ccb20157fbe5eb412bc971d758d072b036a99b06d20853c1f23cdf82085917e08dda2fcfbb5d4d7ee17d74e4988ae81d0308",
            };

            let invalid_sig: Signature = (config.key_type, HexBinary::from_hex(sig_bytes).unwrap())
                .try_into()
                .unwrap();

            let key = KEYS.load(&config.store, (&session.key_id).into()).unwrap();

            let result = session.add_signature(
                key,
                config.signers[0].address.clone().into_string(),
                invalid_sig,
            );

            assert_eq!(
                result.unwrap_err(),
                ContractError::InvalidSignature {
                    session_id: session.id,
                    signer: config.signers[0].address.clone().into_string()
                }
            );
        }
    }

    #[test]
    fn test_add_signature_not_participant() {
        for config in [ecdsa_setup(), ed25519_setup()] {
            let mut session =
                SigningSession::new(Uint64::one(), config.key_id.clone(), config.message.clone());

            let invalid_participant = "not_a_participant".to_string();

            let key = KEYS.load(&config.store, (&session.key_id).into()).unwrap();

            let result = session.add_signature(
                key,
                invalid_participant.clone(),
                Signature::try_from((config.key_type, config.signers[0].signature.clone()))
                    .unwrap(),
            );

            assert_eq!(
                result.unwrap_err(),
                ContractError::NotAParticipant {
                    session_id: session.id,
                    signer: invalid_participant
                }
            );
        }
    }
}
