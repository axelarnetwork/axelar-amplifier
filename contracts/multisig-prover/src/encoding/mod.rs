mod abi;
mod bcs;
mod stellar_xdr;

use axelar_wasm_std::hash::Hash;
use cosmwasm_std::HexBinary;
use error_stack::{bail, Result};
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;
use multisig_prover_api::encoding::Encoder;

use crate::error::ContractError;
use crate::Payload;

pub trait EncoderExt {
    fn digest(
        &self,
        domain_separator: &Hash,
        verifier_set: &VerifierSet,
        payload: &Payload,
    ) -> Result<Hash, ContractError>;

    fn execute_data(
        &self,
        domain_separator: &Hash,
        verifier_set: &VerifierSet,
        sigs: Vec<SignerWithSig>,
        payload: &Payload,
    ) -> Result<HexBinary, ContractError>;
}

impl EncoderExt for Encoder {
    fn digest(
        &self,
        domain_separator: &Hash,
        verifier_set: &VerifierSet,
        payload: &Payload,
    ) -> Result<Hash, ContractError> {
        match self {
            Encoder::Abi => abi::payload_digest(domain_separator, verifier_set, payload),
            Encoder::Bcs => bcs::payload_digest(domain_separator, verifier_set, payload),
            Encoder::StellarXdr => {
                stellar_xdr::payload_digest(domain_separator, verifier_set, payload)
            }
            _ => bail!(ContractError::EncoderNotImplemented),
        }
    }

    fn execute_data(
        &self,
        domain_separator: &Hash,
        verifier_set: &VerifierSet,
        sigs: Vec<SignerWithSig>,
        payload: &Payload,
    ) -> Result<HexBinary, ContractError> {
        match self {
            Encoder::Abi => abi::encode_execute_data(domain_separator, verifier_set, sigs, payload),
            Encoder::Bcs => bcs::encode_execute_data(domain_separator, verifier_set, sigs, payload),
            Encoder::StellarXdr => stellar_xdr::encode_execute_data(verifier_set, sigs, payload),
            _ => bail!(ContractError::EncoderNotImplemented),
        }
    }
}
