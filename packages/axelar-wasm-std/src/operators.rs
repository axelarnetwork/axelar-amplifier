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

#[cfg(test)]
mod tests {
    use super::*;

    use hex;

    // If this test fails, it means the operator hash has changed and therefore a migration is needed.
    #[test]
    fn hash_id_unchaged() {
        let expected_operators_hash =
            "a80417c50895c34c73dee98112e288a3b8dce0d9d77d42cbfbf6bbe29433770b";

        let operators = Operators {
            weights_by_addresses: vec![(
                HexBinary::from_hex("6C51eec96bf0a8ec799cdD0Bbcb4512f8334Afe8").unwrap(),
                Uint256::one(),
            )],
            threshold: Uint256::one(),
        };

        assert_eq!(hex::encode(operators.hash_id()), expected_operators_hash);
    }
}
