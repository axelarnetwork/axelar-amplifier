use crate::types::{EVMAddress, Hash, TMAddress};
use core::result::Result;
use serde::de::{self, Deserializer};
use serde::Deserialize;
use std::fmt::Display;
use std::str::FromStr;
use subtle_encoding::bech32;

pub fn deserialize_hash<'de, D>(deserializer: D) -> Result<Hash, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;

    if bytes.len() != Hash::len_bytes() {
        Err(de::Error::custom(format!("invalid length {} for a hash", bytes.len())))
    } else {
        Ok(Hash::from_slice(&bytes))
    }
}

pub fn deserialize_evm_address<'de, D>(deserializer: D) -> Result<EVMAddress, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;

    if bytes.len() != EVMAddress::len_bytes() {
        Err(de::Error::custom(format!(
            "invalid length {} for an evm address",
            bytes.len()
        )))
    } else {
        Ok(EVMAddress::from_slice(&bytes))
    }
}

pub fn deserialize_tm_addresses<'de, D>(deserializer: D) -> Result<Vec<TMAddress>, D::Error>
where
    D: Deserializer<'de>,
{
    let addresses: Vec<String> = Deserialize::deserialize(deserializer)?;

    addresses
        .iter()
        .map(bech32::decode)
        .collect::<Result<Vec<_>, _>>()
        .map_err(de::Error::custom)?
        .iter()
        .map(|(prefix, bytes)| TMAddress::new(prefix, bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(de::Error::custom)
}

pub fn deserialize_str_to_from_str<'de, D, I>(deserializer: D) -> Result<I, D::Error>
where
    D: Deserializer<'de>,
    I: FromStr,
    <I as FromStr>::Err: Display,
{
    let num: String = Deserialize::deserialize(deserializer)?;
    num.parse::<I>().map_err(de::Error::custom)
}
