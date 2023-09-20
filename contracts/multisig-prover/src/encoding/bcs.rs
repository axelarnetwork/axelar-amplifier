use bcs::to_bytes;
use cosmwasm_std::{HexBinary, Uint256};
use itertools::Itertools;
use multisig::{key::Signature, msg::Signer};

use crate::{error::ContractError, types::Operator};

#[allow(dead_code)]
fn encode_proof(
    quorum: Uint256,
    signers: Vec<(Signer, Option<Signature>)>,
) -> Result<HexBinary, ContractError> {
    let mut operators = make_operators_with_sigs(signers)?;
    operators.sort();

    let (addresses, weights, signatures): (Vec<_>, Vec<u128>, Vec<_>) = operators
        .iter()
        .map(|op| {
            (
                op.address.to_vec(),
                u128::from_le_bytes(
                    op.weight.to_le_bytes()[..16]
                        .try_into()
                        .expect("couldn't convert u256 to u128"),
                )
                .to_le(),
                op.signature.as_ref().map(|sig| sig.as_ref().to_vec()),
            )
        })
        .multiunzip();

    let signatures: Vec<Vec<u8>> = signatures.into_iter().flatten().collect();
    let quorum = &u128::from_le_bytes(
        quorum.to_le_bytes()[..16]
            .try_into()
            .expect("couldn't convert u256 to u128"),
    );
    Ok(to_bytes(&(addresses, weights, quorum, signatures))?.into())
}

#[allow(dead_code)]
fn make_operators_with_sigs(
    signers_with_sigs: Vec<(Signer, Option<Signature>)>,
) -> Result<Vec<Operator>, ContractError> {
    Ok(signers_with_sigs
        .into_iter()
        .map(|(signer, sig)| Operator {
            address: signer.pub_key.into(),
            weight: signer.weight,
            signature: sig,
        })
        .collect())
}

#[cfg(test)]
mod test {

    use std::vec;

    use bcs::from_bytes;
    use cosmwasm_std::{Addr, HexBinary, Uint256};
    use multisig::{
        key::{PublicKey, Signature},
        msg::Signer,
    };

    use super::encode_proof;

    #[test]
    fn test_encode_proof() {
        let signers = vec![
        (Signer {
            address: Addr::unchecked("axelarvaloper1ff675m593vve8yh82lzhdnqfpu7m23cxstr6h4"),
            weight: Uint256::from(10u128),
            pub_key: PublicKey::Ecdsa(
                HexBinary::from_hex(
                    "03c6ddb0fcee7b528da1ef3c9eed8d51eeacd7cc28a8baa25c33037c5562faa6e4",
                )
                .unwrap(),
            ),
        },
        Some(Signature::Ecdsa(
        HexBinary::from_hex("283786d844a7c4d1d424837074d0c8ec71becdcba4dd42b5307cb543a0e2c8b81c10ad541defd5ce84d2a608fc454827d0b65b4865c8192a2ea1736a5c4b72021b").unwrap()))),
            (Signer {
            address: Addr::unchecked("axelarvaloper1x86a8prx97ekkqej2x636utrdu23y8wupp9gk5"),
            weight: Uint256::from(10u128),
            pub_key: PublicKey::Ecdsa(
                HexBinary::from_hex(
                    "03d123ce370b163acd576be0e32e436bb7e63262769881d35fa3573943bf6c6f81",
                )
                .unwrap(),
            ),
        },
        Some(Signature::Ecdsa(
        HexBinary::from_hex("283786d844a7c4d1d424837074d0c8ec71becdcba4dd42b5307cb543a0e2c8b81c10ad541defd5ce84d2a608fc454827d0b65b4865c8192a2ea1736a5c4b72021b").unwrap())))];

        let quorum = Uint256::from(10u128);
        let proof = encode_proof(quorum, signers.clone());

        assert!(proof.is_ok());
        let proof = proof.unwrap();
        let decoded_proof: Result<(Vec<Vec<u8>>, Vec<u128>, u128, Vec<Vec<u8>>), _> =
            from_bytes(&proof);
        assert!(decoded_proof.is_ok());
        let (operators, weights, quorum_decoded, signatures): (
            Vec<Vec<u8>>,
            Vec<u128>,
            u128,
            Vec<Vec<u8>>,
        ) = decoded_proof.unwrap();

        assert_eq!(operators.len(), signers.len());
        assert_eq!(weights.len(), signers.len());
        assert_eq!(signatures.len(), signers.len());
        assert_eq!(quorum_decoded, 10u128);

        for i in 0..signers.len() {
            assert_eq!(
                operators[i],
                HexBinary::from(signers[i].0.pub_key.clone()).to_vec()
            );
            assert_eq!(weights[i], 10u128);
            assert_eq!(
                signatures[i],
                HexBinary::from(signers[i].1.clone().unwrap()).to_vec()
            );
        }
    }
}
