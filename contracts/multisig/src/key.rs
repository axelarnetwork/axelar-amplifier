use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, StdError, StdResult};
use cw_storage_plus::{KeyDeserialize, PrimaryKey};
use serde::{de::Error, Deserialize, Deserializer};

use crate::{ed25519::ed25519_verify, secp256k1::ecdsa_verify, types::MsgToSign, ContractError};

#[cw_serde]
#[derive(Copy)]
pub enum KeyType {
    Ecdsa,
    Ed25519,
}

#[cw_serde]
#[derive(PartialOrd, Ord, Eq)]
pub enum Signature {
    Ecdsa(HexBinary),
    Ed25519(HexBinary),
}

#[cw_serde]
#[derive(Ord, PartialOrd, Eq)]
pub enum PublicKey {
    #[serde(deserialize_with = "deserialize_ecdsa_key")]
    Ecdsa(HexBinary),

    #[serde(deserialize_with = "deserialize_ed25519_key")]
    Ed25519(HexBinary),
}

fn deserialize_ecdsa_key<'de, D>(deserializer: D) -> Result<HexBinary, D::Error>
where
    D: Deserializer<'de>,
{
    let pk: HexBinary = Deserialize::deserialize(deserializer)?;
    PublicKey::try_from((KeyType::Ecdsa, pk.clone()))
        .map_err(|e| D::Error::custom(format!("failed to deserialize public key: {}", e)))?;
    Ok(pk)
}

fn deserialize_ed25519_key<'de, D>(deserializer: D) -> Result<HexBinary, D::Error>
where
    D: Deserializer<'de>,
{
    let pk: HexBinary = Deserialize::deserialize(deserializer)?;
    PublicKey::try_from((KeyType::Ed25519, pk.clone()))
        .map_err(|e| D::Error::custom(format!("failed to deserialize public key: {}", e)))?;
    Ok(pk)
}

pub trait KeyTyped {
    fn matches<T>(&self, other: &T) -> bool
    where
        T: KeyTyped,
    {
        self.key_type() == other.key_type()
    }

    fn key_type(&self) -> KeyType;
}

impl KeyTyped for PublicKey {
    fn key_type(&self) -> KeyType {
        match self {
            PublicKey::Ecdsa(_) => KeyType::Ecdsa,
            PublicKey::Ed25519(_) => KeyType::Ed25519,
        }
    }
}

impl KeyTyped for Signature {
    fn key_type(&self) -> KeyType {
        match self {
            Signature::Ecdsa(_) => KeyType::Ecdsa,
            Signature::Ed25519(_) => KeyType::Ed25519,
        }
    }
}

impl Signature {
    pub fn verify(&self, msg: &MsgToSign, pub_key: &PublicKey) -> Result<bool, ContractError> {
        if !self.matches(pub_key) {
            return Err(ContractError::KeyTypeMismatch);
        }

        match self {
            Signature::Ecdsa(sig) => ecdsa_verify(msg.into(), sig.as_ref(), pub_key.as_ref()),
            Signature::Ed25519(sig) => ed25519_verify(msg.into(), sig.as_ref(), pub_key.as_ref()),
        }
    }
}

impl<'a> PrimaryKey<'a> for KeyType {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<cw_storage_plus::Key> {
        vec![cw_storage_plus::Key::Val8(
            vec![*self as u8]
                .try_into()
                .expect("failed to serialize key type"),
        )]
    }
}

impl KeyDeserialize for KeyType {
    type Output = Self;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        serde_json::from_slice(value.as_slice()).map_err(|err| StdError::ParseErr {
            target_type: "KeyType".into(),
            msg: err.to_string(),
        })
    }
}

const ECDSA_COMPRESSED_PUBKEY_LEN: usize = 33;
const ECDSA_UNCOMPRESSED_PUBKEY_LEN: usize = 65;
const EVM_SIGNATURE_LEN: usize = 65;

const ED25519_PUBKEY_LEN: usize = 32;
const ED25519_SIGNATURE_LEN: usize = 64;

impl TryFrom<(KeyType, HexBinary)> for PublicKey {
    type Error = ContractError;

    fn try_from((key_type, pub_key): (KeyType, HexBinary)) -> Result<Self, Self::Error> {
        match key_type {
            KeyType::Ecdsa => {
                if pub_key.len() != ECDSA_COMPRESSED_PUBKEY_LEN
                    && pub_key.len() != ECDSA_UNCOMPRESSED_PUBKEY_LEN
                {
                    return Err(ContractError::InvalidPublicKeyFormat {
                        reason: "Invalid input length".into(),
                    });
                }
                Ok(PublicKey::Ecdsa(pub_key))
            }

            KeyType::Ed25519 => {
                if pub_key.len() != ED25519_PUBKEY_LEN {
                    return Err(ContractError::InvalidPublicKeyFormat {
                        reason: "Invalid input length".into(),
                    });
                }

                Ok(PublicKey::Ed25519(pub_key))
            }
        }
    }
}

impl TryFrom<(KeyType, HexBinary)> for Signature {
    type Error = ContractError;

    fn try_from((key_type, sig): (KeyType, HexBinary)) -> Result<Self, Self::Error> {
        match key_type {
            KeyType::Ecdsa => {
                if sig.len() != EVM_SIGNATURE_LEN {
                    return Err(ContractError::InvalidSignatureFormat {
                        reason: "Invalid input length".into(),
                    });
                }
                Ok(Signature::Ecdsa(sig))
            }

            KeyType::Ed25519 => {
                if sig.len() != ED25519_SIGNATURE_LEN {
                    return Err(ContractError::InvalidSignatureFormat {
                        reason: "Invalid input length".into(),
                    });
                }

                Ok(Signature::Ed25519(sig))
            }
        }
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            PublicKey::Ecdsa(pk) => pk.as_ref(),
            PublicKey::Ed25519(pk) => pk.as_ref(),
        }
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        match self {
            Signature::Ecdsa(sig) => sig.as_ref(),
            Signature::Ed25519(sig) => sig.as_ref(),
        }
    }
}

impl From<Signature> for Vec<u8> {
    fn from(value: Signature) -> Vec<u8> {
        match value {
            Signature::Ecdsa(sig) => sig.to_vec(),
            Signature::Ed25519(sig) => sig.to_vec(),
        }
    }
}

impl From<Signature> for HexBinary {
    fn from(original: Signature) -> Self {
        match original {
            Signature::Ecdsa(sig) => sig,
            Signature::Ed25519(sig) => sig,
        }
    }
}

impl From<PublicKey> for HexBinary {
    fn from(original: PublicKey) -> Self {
        match original {
            PublicKey::Ecdsa(sig) => sig,
            PublicKey::Ed25519(sig) => sig,
        }
    }
}

#[cfg(test)]
mod ecdsa_tests {
    use cosmwasm_std::HexBinary;

    use crate::{key::Signature, test::common::ecdsa_test_data, types::MsgToSign, ContractError};

    use super::{KeyType, PublicKey};

    #[test]
    fn deserialize_ecdsa_key() {
        let key = PublicKey::try_from((
            KeyType::Ecdsa,
            HexBinary::from_hex(
                "03f57d1a813febaccbe6429603f9ec57969511b76cd680452dba91fa01f54e756d",
            )
            .unwrap(),
        ))
        .unwrap();

        let serialized = serde_json::to_string(&key).unwrap();
        let deserialized: Result<PublicKey, _> = serde_json::from_str(&serialized);
        assert!(deserialized.is_ok());
        assert_eq!(deserialized.unwrap(), key);
    }

    #[test]
    fn deserialize_ecdsa_key_fails() {
        let key = PublicKey::Ecdsa(HexBinary::from_hex("deadbeef").unwrap());

        let serialized = serde_json::to_string(&key).unwrap();
        let deserialized: Result<PublicKey, _> = serde_json::from_str(&serialized);
        assert!(deserialized.is_err());
    }

    #[test]
    fn test_try_from_hexbinary_to_ecdsa_public_key() {
        let hex = ecdsa_test_data::pub_key();
        let pub_key = PublicKey::try_from((KeyType::Ecdsa, hex.clone())).unwrap();
        assert_eq!(HexBinary::from(pub_key), hex);
    }

    #[test]
    fn test_try_from_hexbinary_to_eccdsa_public_key_fails() {
        let hex = HexBinary::from_hex("049b").unwrap();
        assert_eq!(
            PublicKey::try_from((KeyType::Ecdsa, hex.clone())).unwrap_err(),
            ContractError::InvalidPublicKeyFormat {
                reason: "Invalid input length".into()
            }
        );
    }

    #[test]
    fn test_try_from_hexbinary_to_signature() {
        let hex = ecdsa_test_data::signature();
        let signature = Signature::try_from((KeyType::Ecdsa, hex.clone())).unwrap();
        assert_eq!(HexBinary::from(signature), hex);
    }

    #[test]
    fn test_try_from_hexbinary_to_signature_fails() {
        let hex =
            HexBinary::from_hex("283786d844a7c4d1d424837074d0c8ec71becdcba4dd42b5307cb543a0e2c8b81c10ad541defd5ce84d2a608fc454827d0b65b4865c8192a2ea1736a5c4b72")
                .unwrap();
        assert_eq!(
            Signature::try_from((KeyType::Ecdsa, hex.clone())).unwrap_err(),
            ContractError::InvalidSignatureFormat {
                reason: "Invalid input length".into()
            }
        );
    }

    #[test]
    fn test_verify_signature() {
        let signature =
            Signature::try_from((KeyType::Ecdsa, ecdsa_test_data::signature())).unwrap();
        let message = MsgToSign::try_from(ecdsa_test_data::message()).unwrap();
        let public_key = PublicKey::try_from((KeyType::Ecdsa, ecdsa_test_data::pub_key())).unwrap();
        let result = signature.verify(&message, &public_key).unwrap();
        assert_eq!(result, true);
    }

    #[test]
    fn test_verify_signature_invalid_signature() {
        let invalid_signature = HexBinary::from_hex(
            "a112231719403227b297139cc6beef82a4e034663bfe48cf732687860b16227a51e4bd6be96fceeecf8e77fe7cdd4f5567d71aed5388484d1f2ba355298c954e1b",
        )
        .unwrap();

        let signature = Signature::try_from((KeyType::Ecdsa, invalid_signature)).unwrap();
        let message = MsgToSign::try_from(ecdsa_test_data::message()).unwrap();
        let public_key = PublicKey::try_from((KeyType::Ecdsa, ecdsa_test_data::pub_key())).unwrap();
        let result = signature.verify(&message, &public_key).unwrap();
        assert_eq!(result, false);
    }

    #[test]
    fn test_verify_signature_invalid_pub_key() {
        let invalid_pub_key = HexBinary::from_hex(
            "03cd0b61b25b11c59323602dad24336edb9b9a40fb00fdd32c94908967ec16989e",
        )
        .unwrap();

        let signature =
            Signature::try_from((KeyType::Ecdsa, ecdsa_test_data::signature())).unwrap();
        let message = MsgToSign::try_from(ecdsa_test_data::message()).unwrap();
        let public_key = PublicKey::try_from((KeyType::Ecdsa, invalid_pub_key)).unwrap();
        let result = signature.verify(&message, &public_key).unwrap();
        assert_eq!(result, false);
    }
}

#[cfg(test)]
mod ed25519_tests {
    use cosmwasm_std::HexBinary;

    use crate::{key::Signature, test::common::ed25519_test_data, types::MsgToSign, ContractError};

    use super::{KeyType, PublicKey};

    #[test]
    fn deserialize_ed25519_key() {
        let key = PublicKey::try_from((
            KeyType::Ed25519,
            HexBinary::from_hex("d17abc4475ad96b2d9c36f569b6ed1ac8345c562cac906e5f5882230651af574")
                .unwrap(),
        ))
        .unwrap();

        let serialized = serde_json::to_string(&key).unwrap();
        let deserialized: Result<PublicKey, _> = serde_json::from_str(&serialized);
        assert!(deserialized.is_ok());
        assert_eq!(deserialized.unwrap(), key);
    }

    #[test]
    fn deserialize_ed25519_key_fails() {
        let key = PublicKey::Ed25519(HexBinary::from_hex("deadbeef").unwrap());

        let serialized = serde_json::to_string(&key).unwrap();
        let deserialized: Result<PublicKey, _> = serde_json::from_str(&serialized);
        assert!(deserialized.is_err());
    }

    #[test]
    fn test_try_from_hexbinary_to_ed25519_public_key() {
        let hex = ed25519_test_data::pub_key();
        let pub_key = PublicKey::try_from((KeyType::Ed25519, hex.clone())).unwrap();
        assert_eq!(HexBinary::from(pub_key), hex);
    }

    #[test]
    fn test_try_from_hexbinary_to_eccdsa_public_key_fails() {
        let hex = HexBinary::from_hex("049b").unwrap();
        assert_eq!(
            PublicKey::try_from((KeyType::Ed25519, hex.clone())).unwrap_err(),
            ContractError::InvalidPublicKeyFormat {
                reason: "Invalid input length".into()
            }
        );
    }

    #[test]
    fn test_try_from_hexbinary_to_signature() {
        let hex = ed25519_test_data::signature();
        let signature = Signature::try_from((KeyType::Ed25519, hex.clone())).unwrap();
        assert_eq!(HexBinary::from(signature), hex);
    }

    #[test]
    fn test_try_from_hexbinary_to_signature_fails() {
        let hex =
            HexBinary::from_hex("304a300506032b65700341007ac37da74e66005581fa85eaf15a54e0bfcb8c857e3ca4e4bc9e210ed0276bf0792562d474a709c942a488cf53f95823a2d58892981043cd687ccab340cc3907")
                .unwrap();
        assert_eq!(
            Signature::try_from((KeyType::Ed25519, hex.clone())).unwrap_err(),
            ContractError::InvalidSignatureFormat {
                reason: "Invalid input length".into()
            }
        );
    }

    #[test]
    fn test_verify_signature() {
        let signature =
            Signature::try_from((KeyType::Ed25519, ed25519_test_data::signature())).unwrap();
        let message = MsgToSign::try_from(ed25519_test_data::message()).unwrap();
        let public_key =
            PublicKey::try_from((KeyType::Ed25519, ed25519_test_data::pub_key())).unwrap();
        let result = signature.verify(&message, &public_key).unwrap();
        assert_eq!(result, true);
    }

    #[test]
    fn test_verify_signature_invalid_signature() {
        let invalid_signature = HexBinary::from_hex(
            "1fe264eb7258d48d8feedea4d237ccb20157fbe5eb412bc971d758d072b036a99b06d20853c1f23cdf82085917e08dda2fcfbb5d4d7ee17d74e4988ae81d0308",
        )
        .unwrap();

        let signature = Signature::try_from((KeyType::Ed25519, invalid_signature)).unwrap();
        let message = MsgToSign::try_from(ed25519_test_data::message()).unwrap();
        let public_key =
            PublicKey::try_from((KeyType::Ed25519, ed25519_test_data::pub_key())).unwrap();
        let result = signature.verify(&message, &public_key).unwrap();
        assert_eq!(result, false);
    }

    #[test]
    fn test_verify_signature_invalid_pub_key() {
        let invalid_pub_key =
            HexBinary::from_hex("ffff8a3c50c8381541b682f4941ef7df351376f60e3fa0296f48f0f767a4f321")
                .unwrap();

        let signature =
            Signature::try_from((KeyType::Ed25519, ed25519_test_data::signature())).unwrap();
        let message = MsgToSign::try_from(ed25519_test_data::message()).unwrap();
        let public_key = PublicKey::try_from((KeyType::Ed25519, invalid_pub_key)).unwrap();
        let result = signature.verify(&message, &public_key).unwrap();
        assert_eq!(result, false);
    }
}
