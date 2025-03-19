use std::str::FromStr;

use axelar_wasm_std::msg_id::HexTxHash;
use cosmwasm_std::HexBinary;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub fn serialize<S>(value: &HexTxHash, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    HexBinary::from(value.tx_hash.as_ref()).serialize(serializer)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<HexTxHash, D::Error>
where
    D: Deserializer<'de>,
{
    let hex = HexBinary::deserialize(deserializer)?.to_string();
    HexTxHash::from_str(&format!("0x{}", hex)).map_err(Error::custom)
}
