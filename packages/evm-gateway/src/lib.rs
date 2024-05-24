use std::str::FromStr;

use cosmwasm_std::{HexBinary, Uint128, Uint256};
use ethers::{
    abi::{encode, Token::Tuple, Tokenize},
    prelude::abigen,
    types::Address,
};
use multisig::{key::PublicKey, verifier_set::VerifierSet};
use alloy_primitives::{FixedBytes};
use k256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey as k256PubKey};
use sha3::{Digest, Keccak256};
use thiserror::Error;

use axelar_wasm_std::{hash::Hash, operators::Operators};

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

pub fn make_operators(worker_set: VerifierSet) -> Operators {
    let operators: Vec<(HexBinary, Uint128)> = worker_set
        .signers
        .values()
        .map(|signer| {
            (
                evm_address(&signer.pub_key)
                    .expect("couldn't convert pubkey to evm address")
                    .as_slice()
                    .into(),
                signer.weight,
            )
        })
        .collect();
    Operators::new(operators, worker_set.threshold, worker_set.created_at)
}
impl TryFrom<&VerifierSet> for WeightedSigners {
    type Error = Error;
    fn try_from(worker_set: &VerifierSet) -> Result<Self, Error> {
        WeightedSigners::try_from(&make_operators(worker_set.clone()))

    }
}

impl TryFrom<&Operators> for WeightedSigners {
    type Error = Error;

    fn try_from(operators: &Operators) -> Result<Self, Error> {
        let signers = operators
            .weights_by_addresses()
            .iter()
            .map(WeightedSigner::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(WeightedSigners {
            signers,
            threshold: operators.threshold.u128(),
            nonce: Uint256::from(operators.created_at).to_be_bytes(),
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
