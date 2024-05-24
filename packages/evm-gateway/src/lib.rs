use std::str::FromStr;

use alloy_primitives::FixedBytes;
use cosmwasm_std::{HexBinary, Uint128, Uint256};
use ethers::{
    abi::{encode, Token::Tuple, Tokenize},
    prelude::abigen,
    types::Address,
};
use k256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey as k256PubKey};
use multisig::{key::PublicKey, verifier_set::VerifierSet};
use sha3::{Digest, Keccak256};
use thiserror::Error;

use axelar_wasm_std::{hash::Hash};

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

fn evm_address(pub_key: &PublicKey) -> Result<alloy_primitives::Address, Error> {
    match pub_key {
        PublicKey::Ecdsa(pub_key) => k256PubKey::from_sec1_bytes(pub_key)
            .map(|pub_key| pub_key.to_encoded_point(false))
            .map(|pub_key| alloy_primitives::Address::from_raw_public_key(&pub_key.as_bytes()[1..]))
            .map_err(|err| Error::InvalidPublicKey {
                reason: err.to_string(),
            }),
        _ => Err(Error::InvalidPublicKey {
            reason: "expect ECDSA public key".to_string(),
        }),
    }
}


impl TryFrom<&VerifierSet> for WeightedSigners {
    type Error = Error;
    fn try_from(verifier_set: &VerifierSet) -> Result<Self, Error> {
    let signers: Vec<_> = verifier_set
        .signers
        .values()
        .map(|signer| {
            (
                HexBinary::from(evm_address(&signer.pub_key)
                    .expect("couldn't convert pubkey to evm address")
                    .as_slice()),
                signer.weight,
            )
        })
            .map(|e| WeightedSigner::try_from(&e))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(WeightedSigners {
            signers,
            threshold: verifier_set.threshold.u128(),
            nonce: Uint256::from(verifier_set.created_at).to_be_bytes(),
        })
    }
}


impl TryFrom<&(HexBinary, Uint128)> for WeightedSigner {
    type Error = Error;

    fn try_from((address, weight): &(HexBinary, Uint128)) -> Result<Self, Error> {
        let address =
            Address::from_str(&address.to_hex()).map_err(|err| Error::InvalidAddress {
                reason: err.to_string(),
            })?;

        Ok(WeightedSigner {
            signer: address,
            weight: weight.u128(),
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
