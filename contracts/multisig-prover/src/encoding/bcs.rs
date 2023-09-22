use axelar_wasm_std::operators::Operators;
use bcs::to_bytes;
use cosmwasm_std::{HexBinary, Uint256};

use crate::{error::ContractError, state::WorkerSet};

pub fn make_operators(worker_set: WorkerSet) -> Operators {
    let mut operators: Vec<(HexBinary, Uint256)> = worker_set
        .signers
        .iter()
        .map(|signer| (signer.pub_key.clone().into(), signer.weight))
        .collect();
    operators.sort_by_key(|op| op.0.clone());
    Operators {
        weights_by_addresses: operators,
        threshold: worker_set.threshold,
    }
}

fn u256_to_u128(val: Uint256) -> u128 {
    u128::from_le_bytes(
        val.to_le_bytes()[..16]
            .try_into()
            .expect("couldn't convert u256 to u128"),
    )
}

pub fn transfer_operatorship_params(worker_set: &WorkerSet) -> Result<HexBinary, ContractError> {
    let mut operators: Vec<(HexBinary, Uint256)> = worker_set
        .signers
        .iter()
        .map(|s| (s.pub_key.clone().into(), s.weight))
        .collect();
    operators.sort_by_key(|op| op.0.clone());
    let (addresses, weights): (Vec<Vec<u8>>, Vec<_>) = operators
        .into_iter()
        .map(|(pub_key, weight)| (pub_key.to_vec(), u256_to_u128(weight)))
        .unzip();

    Ok(to_bytes(&(addresses, weights, u256_to_u128(worker_set.threshold)))?.into())
}

#[cfg(test)]
mod test {

    use axelar_wasm_std::operators::Operators;
    use bcs::from_bytes;
    use cosmwasm_std::HexBinary;

    use crate::{encoding::bcs::u256_to_u128, test::test_data};

    use super::{make_operators, transfer_operatorship_params};

    #[test]
    fn test_transfer_operatorship_params() {
        let worker_set = test_data::new_worker_set();

        let res = transfer_operatorship_params(&worker_set);
        assert!(res.is_ok());

        let decoded = from_bytes(&res.unwrap());
        assert!(decoded.is_ok());

        let (operators, weights, quorum): (Vec<Vec<u8>>, Vec<u128>, u128) = decoded.unwrap();

        let mut expected: Vec<(Vec<u8>, u128)> = worker_set
            .signers
            .into_iter()
            .map(|s| (s.pub_key.as_ref().to_vec(), u256_to_u128(s.weight)))
            .collect();
        expected.sort_by_key(|op| op.0.clone());
        let (operators_expected, weights_expected): (Vec<Vec<u8>>, Vec<u128>) =
            expected.into_iter().unzip();

        assert_eq!(operators, operators_expected);
        assert_eq!(weights, weights_expected);
        assert_eq!(quorum, u256_to_u128(worker_set.threshold));
    }

    #[test]
    fn test_make_operators() {
        let worker_set = test_data::new_worker_set();
        let mut expected: Vec<(HexBinary, _)> = worker_set
            .clone()
            .signers
            .into_iter()
            .map(|s| (s.pub_key.into(), s.weight))
            .collect();
        expected.sort_by_key(|op| op.0.clone());

        let operators = make_operators(worker_set.clone());
        let expected_operators = Operators {
            weights_by_addresses: expected,
            threshold: worker_set.threshold,
        };
        assert_eq!(operators, expected_operators);
    }
}
