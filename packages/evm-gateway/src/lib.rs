use std::str::FromStr;

use cosmwasm_std::{HexBinary, Uint128, Uint256};
use ethers::{
    abi::{encode, Token::Tuple, Tokenize},
    prelude::abigen,
    types::Address,
};
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
