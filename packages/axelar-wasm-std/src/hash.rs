use cosmwasm_schema::cw_serde;
use cosmwasm_std::{StdError, StdResult};
use cw_storage_plus::{Key, KeyDeserialize, Prefixer, PrimaryKey};

#[cw_serde]
pub struct Hash([u8; 32]);

impl Hash {
    pub fn new(hash: [u8; 32]) -> Self {
        Hash(hash)
    }
}

impl<'a> PrimaryKey<'a> for Hash {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        vec![Key::Ref(&self.0)]
    }
}

impl<'a> Prefixer<'a> for Hash {
    fn prefix(&self) -> Vec<Key> {
        vec![Key::Ref(&self.0)]
    }
}

impl KeyDeserialize for Hash {
    type Output = [u8; 32];

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        <[u8; 32]>::try_from(value).map_err(|v: Vec<_>| StdError::invalid_data_size(32, v.len()))
    }
}

impl KeyDeserialize for &Hash {
    type Output = [u8; 32];

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        Hash::from_vec(value)
    }
}
