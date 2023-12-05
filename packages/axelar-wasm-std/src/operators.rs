use cosmwasm_schema::cw_serde;
use cosmwasm_std::{to_binary, HexBinary, Uint256};

use itertools::Itertools;
use sha3::{Digest, Keccak256};

pub type OperatorsHash = [u8; 32];

#[cw_serde]
pub struct Operators {
    pub weights_by_addresses: Vec<(HexBinary, Uint256)>,
    pub threshold: Uint256,
}

impl Operators {
    pub fn hash(&self) -> OperatorsHash {
        let mut hasher = Keccak256::new();
        hasher.update(
            to_binary(&self.weights_by_addresses.iter().sorted().collect_vec())
                .expect("could not serialize serializable object"),
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
            "9ac8e5863ef6d306ad48dc0fdab30144921b2043b32e72c521dba71627bea747";

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
