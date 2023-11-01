use std::collections::HashMap;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint256, Uint64};

use axelar_wasm_std::Snapshot;

use crate::{
    key::{PublicKey, Signature},
    types::{Key, KeyID, MsgToSign, MultisigState},
    ContractError,
};

#[cw_serde]
pub struct SigningSession {
    pub id: Uint64,
    pub key_id: KeyID,
    pub msg: MsgToSign,
    pub state: MultisigState,
}

impl SigningSession {
    pub fn new(session_id: Uint64, key_id: KeyID, msg: MsgToSign) -> Self {
        Self {
            id: session_id,
            key_id,
            msg,
            state: MultisigState::Pending,
        }
    }

    pub fn recalculate_session_state(
        &mut self,
        signatures: &HashMap<String, Signature>,
        snapshot: &Snapshot,
        block_height: u64,
    ) {
        let weight = signers_weight(signatures, snapshot);

        if self.state == MultisigState::Pending && weight >= snapshot.quorum.into() {
            self.state = MultisigState::Completed {
                completed_at: block_height,
            };
        }
    }
}

pub fn validate_session_signature(
    session: &SigningSession,
    signer: &Addr,
    signature: &Signature,
    pub_key: &PublicKey,
    grace_period: u64,
    block_height: u64,
) -> Result<(), ContractError> {
    if matches!(session.state, MultisigState::Completed { completed_at } if completed_at + grace_period < block_height)
    {
        return Err(ContractError::SigningSessionClosed {
            session_id: session.id,
        });
    }

    if !signature.verify(&session.msg, pub_key)? {
        return Err(ContractError::InvalidSignature {
            session_id: session.id,
            signer: signer.into(),
        });
    }

    Ok(())
}

pub fn signer_pub_key<'a>(
    key: &'a Key,
    signer: &'a Addr,
    session_id: Uint64,
) -> Result<&'a PublicKey, ContractError> {
    match key.pub_keys.get(signer.as_str()) {
        Some(pub_key) => Ok(pub_key),
        None => Err(ContractError::NotAParticipant {
            session_id,
            signer: signer.into(),
        }),
    }
}

fn signers_weight(signatures: &HashMap<String, Signature>, snapshot: &Snapshot) -> Uint256 {
    signatures
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

#[cfg(test)]
mod tests {
    use cosmwasm_std::{testing::MockStorage, Addr, HexBinary};

    use crate::{
        key::KeyType,
        test::common::{build_key, build_snapshot},
        test::common::{ecdsa_test_data, ed25519_test_data},
    };

    use super::*;

    pub struct TestConfig {
        pub store: MockStorage,
        pub key: Key,
        pub session: SigningSession,
        pub signatures: HashMap<String, Signature>,
        pub key_type: KeyType,
    }

    fn ecdsa_setup() -> TestConfig {
        let store = MockStorage::new();

        let signers = ecdsa_test_data::signers();
        let snapshot = build_snapshot(&signers);

        let key_id = KeyID {
            owner: Addr::unchecked("owner"),
            subkey: "subkey".to_string(),
        };
        let key = build_key(KeyType::Ecdsa, key_id, &signers, snapshot);

        let message: MsgToSign = ecdsa_test_data::message().try_into().unwrap();
        let session = SigningSession::new(Uint64::one(), key.id.clone(), message.clone());

        let key_type = KeyType::Ecdsa;
        let signatures: HashMap<String, Signature> = signers
            .iter()
            .map(|signer| {
                (
                    signer.address.clone().into_string(),
                    Signature::try_from((key_type, signer.signature.clone())).unwrap(),
                )
            })
            .collect();

        TestConfig {
            store,
            key,
            session,
            signatures,
            key_type,
        }
    }

    fn ed25519_setup() -> TestConfig {
        let store = MockStorage::new();

        let signers = ed25519_test_data::signers();
        let snapshot = build_snapshot(&signers);

        let key_id = KeyID {
            owner: Addr::unchecked("owner"),
            subkey: "subkey".to_string(),
        };
        let key = build_key(KeyType::Ed25519, key_id, &signers, snapshot);

        let message: MsgToSign = ed25519_test_data::message().try_into().unwrap();
        let session = SigningSession::new(Uint64::one(), key.id.clone(), message.clone());

        let key_type = KeyType::Ed25519;
        let signatures: HashMap<String, Signature> = signers
            .iter()
            .map(|signer| {
                (
                    signer.address.clone().into_string(),
                    Signature::try_from((key_type, signer.signature.clone())).unwrap(),
                )
            })
            .collect();

        TestConfig {
            store,
            key,
            session,
            signatures,
            key_type,
        }
    }

    #[test]
    fn correct_session_state() {
        for config in [ecdsa_setup(), ed25519_setup()] {
            let mut session = config.session;
            let key = config.key;
            let signatures = config.signatures;
            let block_height = 12345;

            session.recalculate_session_state(&HashMap::new(), &key.snapshot, block_height);
            assert_eq!(session.state, MultisigState::Pending);

            session.recalculate_session_state(&signatures, &key.snapshot, block_height);
            assert_eq!(
                session.state,
                MultisigState::Completed {
                    completed_at: block_height
                }
            );
        }
    }

    #[test]
    fn success_validation() {
        for config in [ecdsa_setup(), ed25519_setup()] {
            let session = config.session;
            let key = config.key;
            let signer = Addr::unchecked(config.signatures.keys().next().unwrap());
            let signature = config.signatures.values().next().unwrap();
            let pub_key = signer_pub_key(&key, &signer, session.id).unwrap();

            assert!(
                validate_session_signature(&session, &signer, signature, pub_key, 0, 0).is_ok()
            );
        }
    }

    #[test]
    fn success_validation_grace_period() {
        for config in [ecdsa_setup(), ed25519_setup()] {
            let mut session = config.session;
            let key = config.key;
            let signer = Addr::unchecked(config.signatures.keys().next().unwrap());
            let signature = config.signatures.values().next().unwrap();
            let completed_at = 12345;
            let grace_period = 10;
            let block_height = completed_at + grace_period; // inclusive
            let pub_key = signer_pub_key(&key, &signer, session.id).unwrap();

            session.state = MultisigState::Completed { completed_at };
            assert!(validate_session_signature(
                &session,
                &signer,
                signature,
                pub_key,
                grace_period,
                block_height
            )
            .is_ok());
        }
    }

    #[test]
    fn signing_session_closed_validation() {
        for config in [ecdsa_setup(), ed25519_setup()] {
            let mut session = config.session;
            let key = config.key;
            let signer = Addr::unchecked(config.signatures.keys().next().unwrap());
            let signature = config.signatures.values().next().unwrap();
            let completed_at = 12345;
            let grace_period = 10;
            let block_height = completed_at + grace_period + 1;
            let pub_key = signer_pub_key(&key, &signer, session.id).unwrap();

            session.state = MultisigState::Completed { completed_at };
            let result = validate_session_signature(
                &session,
                &signer,
                signature,
                pub_key,
                grace_period,
                block_height,
            );

            assert_eq!(
                result.unwrap_err(),
                ContractError::SigningSessionClosed {
                    session_id: session.id,
                }
            );
        }
    }

    #[test]
    fn invalid_signature_validation() {
        for config in [ecdsa_setup(), ed25519_setup()] {
            let session = config.session;
            let key = config.key;
            let signer = Addr::unchecked(config.signatures.keys().next().unwrap());
            let pub_key = signer_pub_key(&key, &signer, session.id).unwrap();

            let sig_bytes = match config.key_type {
                KeyType::Ecdsa =>   "a58c9543b9df54578ec45838948e19afb1c6e4c86b34d9899b10b44e619ea74e19b457611e41a047030ed233af437d7ecff84de97cb6b3c13d73d22874e03511",
                KeyType::Ed25519 => "1fe264eb7258d48d8feedea4d237ccb20157fbe5eb412bc971d758d072b036a99b06d20853c1f23cdf82085917e08dda2fcfbb5d4d7ee17d74e4988ae81d0308",
            };

            let invalid_sig: Signature = (config.key_type, HexBinary::from_hex(sig_bytes).unwrap())
                .try_into()
                .unwrap();

            let result = validate_session_signature(&session, &signer, &invalid_sig, pub_key, 0, 0);

            assert_eq!(
                result.unwrap_err(),
                ContractError::InvalidSignature {
                    session_id: session.id,
                    signer: signer.into(),
                }
            );
        }
    }

    #[test]
    fn signer_not_a_participant_validation() {
        for config in [ecdsa_setup(), ed25519_setup()] {
            let session = config.session;
            let key = config.key;
            let invalid_participant = Addr::unchecked("not_a_participant".to_string());

            let result = signer_pub_key(&key, &invalid_participant, session.id);

            assert_eq!(
                result.unwrap_err(),
                ContractError::NotAParticipant {
                    session_id: session.id,
                    signer: invalid_participant.into()
                }
            );
        }
    }
}
