use cosmwasm_std::HexBinary;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub fn serialize<S, const N: usize>(value: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    HexBinary::from(value).serialize(serializer)
}

pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    HexBinary::deserialize(deserializer)?
        .to_array::<N>()
        .map_err(Error::custom)
}
