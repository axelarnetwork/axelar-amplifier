use std::collections::HashMap;

use axelar_wasm_std::Snapshot;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, StdError, Storage, Uint256, Uint64};

use crate::{
    state::{KEYS, SIGNING_SESSIONS},
    ContractError,
};

pub trait VerifiableSignature {
    fn verify(&self, msg: &Message, pub_key: &PublicKey) -> Result<bool, ContractError>;
}

#[cw_serde]
pub struct PublicKey(HexBinary);

impl From<PublicKey> for HexBinary {
    fn from(original: PublicKey) -> Self {
        original.0
    }
}

impl<'a> From<&'a PublicKey> for &'a [u8] {
    fn from(original: &'a PublicKey) -> Self {
        original.0.as_slice()
    }
}

impl PublicKey {
    pub fn unchecked(hex: HexBinary) -> Self {
        Self(hex)
    }
}

#[cw_serde]
pub struct Message(HexBinary);

impl From<Message> for HexBinary {
    fn from(original: Message) -> Self {
        original.0
    }
}

impl<'a> From<&'a Message> for &'a [u8] {
    fn from(original: &'a Message) -> Self {
        original.0.as_slice()
    }
}

impl Message {
    pub fn unchecked(hex: HexBinary) -> Self {
        Self(hex)
    }
}

#[cw_serde]
pub struct Signature(HexBinary);

impl From<Signature> for HexBinary {
    fn from(original: Signature) -> Self {
        original.0
    }
}

impl<'a> From<&'a Signature> for &'a [u8] {
    fn from(original: &'a Signature) -> Self {
        original.0.as_slice()
    }
}

impl Signature {
    pub fn unchecked(hex: HexBinary) -> Self {
        Self(hex)
    }
}

#[cw_serde]
pub struct Key {
    pub id: String,
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
    pub key_id: String,
    pub msg: Message,
    pub signatures: HashMap<String, Signature>,
    pub state: MultisigState,
}

impl SigningSession {
    pub fn new(sig_id: Uint64, key_id: String, msg: Message) -> Self {
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
        store: &mut dyn Storage, // TODO: use mutable and update storage in same function?
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

        SIGNING_SESSIONS.save(store, self.id.into(), self)?;

        Ok(())
    }

    pub fn key(&self, store: &dyn Storage) -> Result<Key, StdError> {
        KEYS.load(store, self.key_id.clone())
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

#[cfg(test)]
mod tests {
    use super::*;

    use axelar_wasm_std::{nonempty, Participant, Threshold};
    use cosmwasm_std::{testing::MockStorage, Addr, Timestamp};
    use rand::Rng;

    #[derive(Clone)]
    pub struct TestSigner {
        pub address: Addr,
        pub pub_key: PublicKey,
        pub signature: Signature,
    }

    pub struct TestConfig {
        pub store: MockStorage,
        pub key_id: String,
        pub message: Message,
        pub signers: Vec<TestSigner>,
    }

    fn setup() -> TestConfig {
        let mut store = MockStorage::new();
        let mut rng = rand::thread_rng();

        let signers = vec![
            TestSigner {
                address: Addr::unchecked("signer1"),
                pub_key: HexBinary::from_hex(
                    "03f57d1a813febaccbe6429603f9ec57969511b76cd680452dba91fa01f54e756d",
                )
                .unwrap()
                .try_into()
                .unwrap(),
                signature: HexBinary::from_hex("283786d844a7c4d1d424837074d0c8ec71becdcba4dd42b5307cb543a0e2c8b81c10ad541defd5ce84d2a608fc454827d0b65b4865c8192a2ea1736a5c4b72021b")
                .unwrap().try_into().unwrap(),
            },
            TestSigner {
                address: Addr::unchecked("signer2"),
                pub_key: HexBinary::from_hex(
                    "03f57d1a813febaccbe6429603f9ec57969511b76cd680452dba91fa01f54e756d",
                )
                .unwrap()
                .try_into()
                .unwrap(),
                signature: HexBinary::from_hex("283786d844a7c4d1d424837074d0c8ec71becdcba4dd42b5307cb543a0e2c8b81c10ad541defd5ce84d2a608fc454827d0b65b4865c8192a2ea1736a5c4b72021b")
                .unwrap().try_into().unwrap(),
            },
            TestSigner {
                address: Addr::unchecked("signer3"),
                pub_key: HexBinary::from_hex(
                    "03f57d1a813febaccbe6429603f9ec57969511b76cd680452dba91fa01f54e756d",
                )
                .unwrap()
                .try_into()
                .unwrap(),
                signature: HexBinary::from_hex("283786d844a7c4d1d424837074d0c8ec71becdcba4dd42b5307cb543a0e2c8b81c10ad541defd5ce84d2a608fc454827d0b65b4865c8192a2ea1736a5c4b72021b")
                .unwrap().try_into().unwrap(),
            }
        ];

        let participants = signers
            .iter()
            .map(|signer| Participant {
                address: signer.address.clone(),
                weight: Uint256::one().try_into().unwrap(),
            })
            .collect::<Vec<_>>();

        let snapshot = Snapshot::new(
            Timestamp::from_nanos(rng.gen()).try_into().unwrap(),
            nonempty::Uint64::try_from(rng.gen::<u64>()).unwrap(),
            Threshold::try_from((2u64, 3u64)).unwrap(),
            nonempty::Vec::try_from(participants).unwrap(),
        );

        let pub_keys = signers
            .iter()
            .map(|signer| (signer.address.clone().to_string(), signer.pub_key.clone()))
            .collect::<HashMap<_, _>>();

        let key_id = "key_id".to_string();
        let key = Key {
            id: key_id.clone(),
            snapshot,
            pub_keys,
        };
        KEYS.save(&mut store, key_id.clone(), &key).unwrap();

        let message: Message =
            HexBinary::from_hex("fa0609efd1dfeedfdcc8ba51520fae2d5176b7621d2560f071e801b0817e1537")
                .unwrap()
                .try_into()
                .unwrap();

        TestConfig {
            store,
            key_id,
            message,
            signers,
        }
    }

    fn sign(
        session: &mut SigningSession,
        signer_ix: usize,
        config: &mut TestConfig,
    ) -> Result<(), ContractError> {
        let signer = config.signers[signer_ix].clone();

        session.add_signature(
            &mut config.store,
            signer.address.clone().into_string(),
            signer.signature.clone(),
        )
    }

    #[test]
    fn test_add_signature() {
        let mut config = setup();

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
                sig_id: session.id,
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
            ContractError::SigningSessionClosed { sig_id: session.id }
        );
        assert_eq!(session.signatures.len(), 2);
        assert_eq!(session.state, MultisigState::Completed);
        assert_eq!(stored, session);
    }

    #[test]
    fn test_add_invalid_signature() {
        let mut config = setup();

        let mut session =
            SigningSession::new(Uint64::one(), config.key_id.clone(), config.message.clone());

        let invalid_sig: Signature = HexBinary::from_hex("a58c9543b9df54578ec45838948e19afb1c6e4c86b34d9899b10b44e619ea74e19b457611e41a047030ed233af437d7ecff84de97cb6b3c13d73d22874e035111c")
                .unwrap().try_into().unwrap();

        let result = session.add_signature(
            &mut config.store,
            config.signers[0].address.clone().into_string(),
            invalid_sig,
        );

        assert_eq!(
            result.unwrap_err(),
            ContractError::InvalidSignature {
                sig_id: session.id,
                signer: config.signers[0].address.clone().into_string()
            }
        );
    }

    #[test]
    fn test_add_signature_not_participant() {
        let mut config = setup();

        let mut session =
            SigningSession::new(Uint64::one(), config.key_id.clone(), config.message.clone());

        let invalid_participant = "not_a_participant".to_string();

        let result = session.add_signature(
            &mut config.store,
            invalid_participant.clone(),
            config.signers[0].signature.clone(),
        );

        assert_eq!(
            result.unwrap_err(),
            ContractError::NotAParticipant {
                sig_id: session.id,
                signer: invalid_participant
            }
        );
    }
}
