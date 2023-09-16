use std::{collections::HashMap, fmt};

use axelar_wasm_std::Snapshot;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{from_binary, Addr, HexBinary, StdResult};
use cw_storage_plus::{KeyDeserialize, PrimaryKey};

use crate::key::PublicKey;
use crate::ContractError;

#[cw_serde]
pub struct MsgToSign(HexBinary);

impl From<MsgToSign> for HexBinary {
    fn from(original: MsgToSign) -> Self {
        original.0
    }
}

impl<'a> From<&'a MsgToSign> for &'a [u8] {
    fn from(original: &'a MsgToSign) -> Self {
        original.0.as_slice()
    }
}

impl MsgToSign {
    pub fn unchecked(hex: HexBinary) -> Self {
        Self(hex)
    }
}

#[cw_serde]
pub struct KeyID {
    pub owner: Addr,
    pub subkey: String,
}

impl<'a> PrimaryKey<'a> for &KeyID {
    type Prefix = Addr;
    type SubPrefix = ();
    type Suffix = String;
    type SuperSuffix = KeyID;

    fn key(&self) -> std::vec::Vec<cw_storage_plus::Key<'_>> {
        let mut keys = self.owner.key();
        keys.extend(self.subkey.key());
        keys
    }
}

impl KeyDeserialize for KeyID {
    type Output = KeyID;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        Ok(from_binary(&value.into()).expect("violated invariant: KeyID is not deserializable"))
    }
}

impl fmt::Display for KeyID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {})", self.owner, self.subkey)
    }
}

#[cw_serde]
pub struct Key {
    pub id: KeyID,
    pub snapshot: Snapshot,
    pub pub_keys: HashMap<String, PublicKey>,
}

#[cw_serde]
pub enum MultisigState {
    Pending,
    Completed,
}

const MESSAGE_HASH_LEN: usize = 32;

impl TryFrom<HexBinary> for MsgToSign {
    type Error = ContractError;

    fn try_from(other: HexBinary) -> Result<Self, Self::Error> {
        if other.len() != MESSAGE_HASH_LEN {
            return Err(ContractError::InvalidMessageFormat {
                reason: "Invalid input length".into(),
            });
        }

        Ok(MsgToSign::unchecked(other))
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::to_binary;

    use crate::test::common::test_data;

    use super::*;

    #[test]
    fn test_key_deserialize() {
        let key = KeyID {
            owner: Addr::unchecked("owner".to_string()),
            subkey: "subkey".to_string(),
        };

        let serialized = to_binary(&key).unwrap();

        assert_eq!(key, KeyID::from_vec(serialized.into()).unwrap());
    }

    #[test]
    fn test_try_from_hexbinary_to_message() {
        let hex = test_data::message();
        let message = MsgToSign::try_from(hex.clone()).unwrap();
        assert_eq!(HexBinary::from(message), hex);
    }

    #[test]
    fn test_try_from_hexbinary_to_message_fails() {
        let hex = HexBinary::from_hex("283786d844a7c4d1d424837074d0c8ec71becdcba4dd42b5307cb543a0e2c8b81c10ad541defd5ce84d2a608fc454827d0b65b4865c8192a2ea1736a5c4b72021b").unwrap();
        assert_eq!(
            MsgToSign::try_from(hex.clone()).unwrap_err(),
            ContractError::InvalidMessageFormat {
                reason: "Invalid input length".into()
            }
        );
    }
}
