use cosmwasm_std::HexBinary;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[cfg_attr(dylint_lib = "amplifier_lints", allow(ref_opt_type))]
pub fn serialize<S, const N: usize>(
    value: &Option<[u8; N]>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(array) => HexBinary::from(array).serialize(serializer),
        None => serializer.serialize_none(),
    }
}

pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<Option<[u8; N]>, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<HexBinary>::deserialize(deserializer)? {
        Some(hex) => hex.to_array::<N>().map(Some).map_err(Error::custom),
        None => Ok(None),
    }
}
