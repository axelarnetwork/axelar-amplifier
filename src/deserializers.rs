use std::fmt::Display;
use std::str::FromStr;

use core::result::Result;

use serde::de::{self, Deserializer};
use serde::Deserialize;
use serde_json::Value;

pub fn from_str<'de, D, I>(deserializer: D) -> Result<I, D::Error>
where
    D: Deserializer<'de>,
    I: FromStr,
    <I as FromStr>::Err: Display,
{
    let value: Value = Deserialize::deserialize(deserializer)?;
    value.to_string().parse::<I>().map_err(de::Error::custom)
}
