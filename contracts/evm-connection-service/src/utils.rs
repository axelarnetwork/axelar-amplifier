use std::{collections::hash_map::DefaultHasher, hash::Hasher};

use cosmwasm_std::to_binary;
use serde::Serialize;

pub fn hash<T>(data: &T) -> u64
where
    T: Serialize + ?Sized,
{
    let bytes = to_binary(data).unwrap();

    let mut hasher = DefaultHasher::new();
    hasher.write(&bytes);

    hasher.finish()
}
