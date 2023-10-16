use cosmwasm_std::HexBinary;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    HexBinary::from(value).serialize(serializer)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
    HexBinary::deserialize(deserializer)?
        .to_array::<32>()
        .map_err(|err| Error::custom(err))
}
