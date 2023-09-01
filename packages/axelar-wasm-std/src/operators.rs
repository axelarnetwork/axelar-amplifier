use cosmwasm_schema::cw_serde;
use cosmwasm_std::{to_vec, HexBinary, Uint256};

use sha3::{Digest, Keccak256};

#[cw_serde]
pub struct Operators {
    pub weights_by_addresses: Vec<(HexBinary, Uint256)>,
    pub threshold: Uint256,
}

impl Operators {
    pub fn hash(&self) -> Vec<u8> {
        Keccak256::digest(to_vec(self).expect("could not convert Operators to vec"))
            .as_slice()
            .into()
    }
}
