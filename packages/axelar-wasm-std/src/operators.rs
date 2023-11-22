use cosmwasm_schema::cw_serde;
use cosmwasm_std::{to_binary, HexBinary, Uint256};

use sha3::{Digest, Keccak256};

pub type OperatorsHash = [u8; 32];
#[cw_serde]
pub struct Operators {
    pub weights_by_addresses: Vec<(HexBinary, Uint256)>,
    pub threshold: Uint256,
}

impl Operators {
    pub fn hash_id(&self) -> OperatorsHash {
        let mut hasher = Keccak256::new();
        hasher.update(
            to_binary(&self.weights_by_addresses).expect("could not serialize serializable object"),
        );
        hasher.update(self.threshold.to_be_bytes());
        hasher.finalize().into()
    }
}
