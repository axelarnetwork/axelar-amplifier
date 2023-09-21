use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, StdError, StdResult};
use cw_storage_plus::{KeyDeserialize, PrimaryKey};
use serde::{de::Error, Deserializer};

use crate::{secp256k1::ecdsa_verify, types::MsgToSign, ContractError};

#[cw_serde]
#[derive(Copy)]
pub enum KeyType {
    Ecdsa,
}

#[cw_serde]
#[derive(PartialOrd, Ord, Eq)]
pub enum Signature {
    Ecdsa(HexBinary),
}

#[cw_serde]
#[derive(Ord, PartialOrd, Eq)]
pub enum PublicKey {
    #[serde(deserialize_with = "deserialize_ecdsa_key")]
    Ecdsa(HexBinary),
}

use serde::Deserialize;
fn deserialize_ecdsa_key<'de, D>(deserializer: D) -> Result<HexBinary, D::Error>
where
    D: Deserializer<'de>,
{
    let pk: HexBinary = Deserialize::deserialize(deserializer)?;
    PublicKey::try_from((KeyType::Ecdsa, pk.clone()))
        .map_err(|err| D::Error::custom(format!("failed to deserialize public key: {}", err)))?;
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
        }
    }
}

impl KeyTyped for Signature {
    fn key_type(&self) -> KeyType {
        match self {
            Signature::Ecdsa(_) => KeyType::Ecdsa,
        }
    }
}

impl Signature {
    pub fn verify(&self, msg: &MsgToSign, pub_key: &PublicKey) -> Result<bool, ContractError> {
        if !self.matches(pub_key) {
            return Err(ContractError::KeyTypeMismatch);
        }

        match (self, pub_key) {
            (Signature::Ecdsa(sig), PublicKey::Ecdsa(pub_key)) => {
                ecdsa_verify(msg.into(), sig.as_ref(), pub_key.as_ref())
            }
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
        }
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            PublicKey::Ecdsa(pk) => pk.as_ref(),
        }
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        match self {
            Signature::Ecdsa(sig) => sig.as_ref(),
        }
    }
}

impl From<Signature> for Vec<u8> {
    fn from(value: Signature) -> Vec<u8> {
        match value {
            Signature::Ecdsa(sig) => sig.to_vec(),
        }
    }
}

impl From<Signature> for HexBinary {
    fn from(original: Signature) -> Self {
        match original {
            Signature::Ecdsa(sig) => sig,
        }
    }
}

impl From<PublicKey> for HexBinary {
    fn from(original: PublicKey) -> Self {
        match original {
            PublicKey::Ecdsa(sig) => sig,
        }
    }
}

#[cfg(test)]
mod test {
    use cosmwasm_std::HexBinary;

    use crate::{key::Signature, test::common::test_data, types::MsgToSign, ContractError};

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
        let hex = test_data::pub_key();
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
        let hex = test_data::signature();
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
        let signature = Signature::try_from((KeyType::Ecdsa, test_data::signature())).unwrap();
        let message = MsgToSign::try_from(test_data::message()).unwrap();
        let public_key = PublicKey::try_from((KeyType::Ecdsa, test_data::pub_key())).unwrap();
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
        let message = MsgToSign::try_from(test_data::message()).unwrap();
        let public_key = PublicKey::try_from((KeyType::Ecdsa, test_data::pub_key())).unwrap();
        let result = signature.verify(&message, &public_key).unwrap();
        assert_eq!(result, false);
    }

    #[test]
    fn test_verify_signature_invalid_pub_key() {
        let invalid_pub_key = HexBinary::from_hex(
            "03cd0b61b25b11c59323602dad24336edb9b9a40fb00fdd32c94908967ec16989e",
        )
        .unwrap();

        let signature = Signature::try_from((KeyType::Ecdsa, test_data::signature())).unwrap();
        let message = MsgToSign::try_from(test_data::message()).unwrap();
        let public_key = PublicKey::try_from((KeyType::Ecdsa, invalid_pub_key)).unwrap();
        let result = signature.verify(&message, &public_key).unwrap();
        assert_eq!(result, false);
    }
}
