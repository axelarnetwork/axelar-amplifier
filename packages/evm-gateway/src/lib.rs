use cosmwasm_std::Uint256;
use ethers::{
    abi::{encode, Token::Tuple, Tokenize},
    prelude::abigen,
    types::Address,
    utils::public_key_to_address,
};
use k256::ecdsa::VerifyingKey;
use sha3::{Digest, Keccak256};
use thiserror::Error;

use axelar_wasm_std::hash::Hash;
use multisig::{key::PublicKey, msg::Signer, verifier_set::VerifierSet};

// Generates the bindings for the Axelar Amplifier Gateway contract.
// This includes the defined structs: Messages, WeightedSigners, WeightedSigner, and Proofs.
abigen!(
    IAxelarAmplifierGateway,
    "src/abi/$SOLIDITY_GATEWAY_VERSION/IAxelarAmplifierGateway.json"
);

#[derive(Error, Debug)]
pub enum Error {
    #[error("address is invalid: {reason}")]
    InvalidAddress { reason: String },
    #[error("public key is invalid: {reason}")]
    InvalidPublicKey { reason: String },
}

impl TryFrom<&VerifierSet> for WeightedSigners {
    type Error = Error;

    fn try_from(verifier_set: &VerifierSet) -> Result<Self, Error> {
        let mut signers: Vec<_> = verifier_set
            .signers
            .values()
            .map(WeightedSigner::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        signers.sort_by_key(|weighted_signer| weighted_signer.signer);

        Ok(WeightedSigners {
            signers,
            threshold: verifier_set.threshold.u128(),
            nonce: Uint256::from(verifier_set.created_at).to_be_bytes(),
        })
    }
}

impl TryFrom<&Signer> for WeightedSigner {
    type Error = Error;

    fn try_from(signer: &Signer) -> Result<Self, Error> {
        Ok(WeightedSigner {
            signer: evm_address(&signer.pub_key)?,
            weight: signer.weight.u128(),
        })
    }
}

impl WeightedSigners {
    pub fn abi_encode(&self) -> Vec<u8> {
        let tokens = self.clone().into_tokens();

        encode(&[Tuple(tokens)])
    }

    pub fn hash(&self) -> Hash {
        Keccak256::digest(self.abi_encode()).into()
    }
}

fn evm_address(pub_key: &PublicKey) -> Result<Address, Error> {
    match pub_key {
        PublicKey::Ecdsa(pub_key) => VerifyingKey::from_sec1_bytes(pub_key)
            .map(|v| public_key_to_address(&v))
            .map_err(|err| Error::InvalidPublicKey {
                reason: err.to_string(),
            }),
        _ => Err(Error::InvalidPublicKey {
            reason: "expect ECDSA public key".to_string(),
        }),
    }
}

#[cfg(test)]
mod test {
    use cosmwasm_std::{Addr, HexBinary, Uint128};

    use axelar_wasm_std::{nonempty, snapshot::Participant};
    use multisig::{key::PublicKey, verifier_set::VerifierSet};

    use crate::WeightedSigners;

    #[test]
    fn weight_signers_hash() {
        let expected_hash =
            HexBinary::from_hex("e490c7e55a46b0e1e39a3034973b676eed044fed387f80f4e6377305313f8762")
                .unwrap();
        let verifier_set = curr_verifier_set();

        assert_eq!(
            WeightedSigners::try_from(&verifier_set).unwrap().hash(),
            expected_hash
        );
    }

    // Generate a worker set matches axelar-gmp-sdk-solidity repo test data
    pub fn curr_verifier_set() -> VerifierSet {
        let pub_keys = vec![
            "038318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75",
            "02ba5734d8f7091719471e7f7ed6b9df170dc70cc661ca05e688601ad984f068b0",
            "039d9031e97dd78ff8c15aa86939de9b1e791066a0224e331bc962a2099a7b1f04",
            "0220b871f3ced029e14472ec4ebc3c0448164942b123aa6af91a3386c1c403e0eb",
            "03bf6ee64a8d2fdc551ec8bb9ef862ef6b4bcb1805cdc520c3aa5866c0575fd3b5",
        ];

        verifier_set_from_pub_keys(pub_keys)
    }

    pub fn verifier_set_from_pub_keys(pub_keys: Vec<&str>) -> VerifierSet {
        let participants: Vec<(_, _)> = (0..pub_keys.len())
            .map(|i| {
                (
                    Participant {
                        address: Addr::unchecked(format!("verifier{i}")),
                        weight: nonempty::Uint128::one(),
                    },
                    PublicKey::Ecdsa(HexBinary::from_hex(pub_keys[i]).unwrap()),
                )
            })
            .collect();
        VerifierSet::new(participants, Uint128::from(3u128), 0)
    }
}
