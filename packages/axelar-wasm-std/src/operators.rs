use cosmwasm_schema::cw_serde;
use cosmwasm_std::{to_binary, HexBinary, Uint256};

use sha3::{Digest, Keccak256};

use crate::hash::Hash;

#[cw_serde]
pub struct Operators {
    weights_by_addresses: Vec<(HexBinary, Uint256)>,
    pub threshold: Uint256,
}

impl Operators {
    pub fn new(mut weights_by_addresses: Vec<(HexBinary, Uint256)>, threshold: Uint256) -> Self {
        weights_by_addresses.sort_by_key(|op| op.0.clone());

        Self {
            weights_by_addresses,
            threshold,
        }
    }

    pub fn hash(&self) -> Hash {
        let mut hasher = Keccak256::new();
        hasher.update(
            to_binary(&self.weights_by_addresses).expect("could not serialize serializable object"),
        );
        hasher.update(self.threshold.to_be_bytes());
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex;

    // If this test fails, it means the operator hash has changed and therefore a migration is needed.
    #[test]
    fn hash_id_unchanged() {
        let expected_operators_hash =
            "99644dc48547a984edaabc9b0a2592d9a29d721be075a561ec2cfa644f5dc918";

        let operators = Operators {
            weights_by_addresses: vec![
                (
                    HexBinary::from_hex("6C51eec96bf0a8ec799cdD0Bbcb4512f8334Afe8").unwrap(),
                    Uint256::one(),
                ),
                (
                    HexBinary::from_hex("11C67adfe52a3782bd518294188C4AAfaaF6cDeb").unwrap(),
                    Uint256::one(),
                ),
                (
                    HexBinary::from_hex("4905FD2e40B1A037256e32fe1e4BCa41AE510d73").unwrap(),
                    Uint256::one(),
                ),
            ],
            threshold: Uint256::one(),
        };

        assert_eq!(hex::encode(operators.hash()), expected_operators_hash);
    }
}
