use std::collections::HashMap;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint256, Uint64};

use crate::{
    key::{PublicKey, Signature},
    types::{MsgToSign, MultisigState},
    worker_set::WorkerSet,
    ContractError,
};

#[cw_serde]
pub struct SigningSession {
    pub id: Uint64,
    pub worker_set_id: String,
    pub msg: MsgToSign,
    pub state: MultisigState,
    pub expires_at: u64,
}

impl SigningSession {
    pub fn new(session_id: Uint64, worker_set_id: String, msg: MsgToSign, expires_at: u64) -> Self {
        Self {
            id: session_id,
            worker_set_id,
            msg,
            state: MultisigState::Pending,
            expires_at,
        }
    }

    pub fn recalculate_session_state(
        &mut self,
        signatures: &HashMap<String, Signature>,
        worker_set: &WorkerSet,
        block_height: u64,
    ) {
        let weight = signers_weight(signatures, worker_set);

        if self.state == MultisigState::Pending && weight >= worker_set.threshold {
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
    block_height: u64,
) -> Result<(), ContractError> {
    if session.expires_at < block_height {
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

fn signers_weight(signatures: &HashMap<String, Signature>, worker_set: &WorkerSet) -> Uint256 {
    signatures
        .keys()
        .map(|addr| -> Uint256 {
            worker_set
                .signers
                .get(addr)
                .expect("violated invariant: signature submitted by non-participant")
                .weight
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::{testing::MockStorage, Addr, HexBinary};

    use crate::{
        key::KeyType,
        test::common::build_worker_set,
        test::common::{ecdsa_test_data, ed25519_test_data},
    };

    use super::*;

    pub struct TestConfig {
        pub store: MockStorage,
        pub worker_set: WorkerSet,
        pub session: SigningSession,
        pub signatures: HashMap<String, Signature>,
        pub key_type: KeyType,
    }

    fn ecdsa_setup() -> TestConfig {
        let store = MockStorage::new();

        let signers = ecdsa_test_data::signers();

        let worker_set_id = "subkey".to_string();
        let key_type = KeyType::Ecdsa;
        let worker_set = build_worker_set(KeyType::Ecdsa, &signers);

        let message: MsgToSign = ecdsa_test_data::message().try_into().unwrap();
        let expires_at = 12345;
        let session =
            SigningSession::new(Uint64::one(), worker_set_id, message.clone(), expires_at);

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
            worker_set,
            session,
            signatures,
            key_type,
        }
    }

    fn ed25519_setup() -> TestConfig {
        let store = MockStorage::new();

        let signers = ed25519_test_data::signers();

        let worker_set_id = "subkey".to_string();
        let key_type = KeyType::Ed25519;
        let worker_set = build_worker_set(key_type, &signers);

        let message: MsgToSign = ed25519_test_data::message().try_into().unwrap();
        let expires_at = 12345;
        let session =
            SigningSession::new(Uint64::one(), worker_set_id, message.clone(), expires_at);

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
            worker_set,
            session,
            signatures,
            key_type,
        }
    }

    #[test]
    fn correct_session_state() {
        for config in [ecdsa_setup(), ed25519_setup()] {
            let mut session = config.session;
            let worker_set = config.worker_set;
            let signatures = config.signatures;
            let block_height = 12345;

            session.recalculate_session_state(&HashMap::new(), &worker_set, block_height);
            assert_eq!(session.state, MultisigState::Pending);

            session.recalculate_session_state(&signatures, &worker_set, block_height);
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
            let worker_set = config.worker_set;
            let signer = Addr::unchecked(config.signatures.keys().next().unwrap());
            let signature = config.signatures.values().next().unwrap();
            let pub_key = &worker_set.signers.get(&signer.to_string()).unwrap().pub_key;

            assert!(validate_session_signature(&session, &signer, signature, pub_key, 0).is_ok());
        }
    }

    #[test]
    fn success_validation_expiry_not_reached() {
        for config in [ecdsa_setup(), ed25519_setup()] {
            let mut session = config.session;
            let worker_set = config.worker_set;
            let signer = Addr::unchecked(config.signatures.keys().next().unwrap());
            let signature = config.signatures.values().next().unwrap();
            let block_height = 12340; // inclusive
            let pub_key = &worker_set.signers.get(&signer.to_string()).unwrap().pub_key;

            assert!(validate_session_signature(
                &session,
                &signer,
                signature,
                pub_key,
                block_height
            )
            .is_ok());
        }
    }

    #[test]
    fn signing_session_closed_validation() {
        for config in [ecdsa_setup(), ed25519_setup()] {
            let mut session = config.session;
            let worker_set = config.worker_set;
            let signer = Addr::unchecked(config.signatures.keys().next().unwrap());
            let signature = config.signatures.values().next().unwrap();
            let block_height = 12346;
            let pub_key = &worker_set.signers.get(&signer.to_string()).unwrap().pub_key;

            let result =
                validate_session_signature(&session, &signer, signature, pub_key, block_height);

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
            let worker_set = config.worker_set;
            let signer = Addr::unchecked(config.signatures.keys().next().unwrap());
            let pub_key = &worker_set.signers.get(&signer.to_string()).unwrap().pub_key;

            let sig_bytes = match config.key_type {
                KeyType::Ecdsa =>   "a58c9543b9df54578ec45838948e19afb1c6e4c86b34d9899b10b44e619ea74e19b457611e41a047030ed233af437d7ecff84de97cb6b3c13d73d22874e03511",
                KeyType::Ed25519 => "1fe264eb7258d48d8feedea4d237ccb20157fbe5eb412bc971d758d072b036a99b06d20853c1f23cdf82085917e08dda2fcfbb5d4d7ee17d74e4988ae81d0308",
            };

            let invalid_sig: Signature = (config.key_type, HexBinary::from_hex(sig_bytes).unwrap())
                .try_into()
                .unwrap();

            let result = validate_session_signature(&session, &signer, &invalid_sig, pub_key, 0);

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
            let worker_set = config.worker_set;
            let invalid_participant = Addr::unchecked("not_a_participant".to_string());

            let result = match worker_set.signers.get(&invalid_participant.to_string()) {
                Some(signer) => Ok(&signer.pub_key),
                None => Err(ContractError::NotAParticipant {
                    session_id: session.id,
                    signer: invalid_participant.to_string(),
                }),
            };

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
