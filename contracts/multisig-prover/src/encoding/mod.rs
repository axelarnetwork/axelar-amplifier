mod abi;
mod bcs;
mod stellar_xdr;

use axelar_wasm_std::hash::Hash;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::HexBinary;
use error_stack::Result;
use multisig::key::Signature;
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;

use crate::error::ContractError;
use crate::payload::Payload;

#[cw_serde]
#[derive(Copy)]
pub enum Encoder {
    Abi,
    Bcs,
    StellarXdr,
}

impl Encoder {
    pub fn digest(
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
        }
    }

    pub fn execute_data(
        &self,
        domain_separator: &Hash,
        verifier_set: &VerifierSet,
        sigs: Vec<SignerWithSig>,
        payload: &Payload,
    ) -> Result<HexBinary, ContractError> {
        match self {
            Encoder::Abi => abi::execute_data::encode(
                verifier_set,
                sigs,
                &self.digest(domain_separator, verifier_set, payload)?,
                payload,
            ),
            Encoder::Bcs => bcs::encode_execute_data(
                verifier_set,
                sigs,
                &self.digest(domain_separator, verifier_set, payload)?,
                payload,
            ),
            Encoder::StellarXdr => todo!(),
        }
    }
}

// Convert non-recoverable ECDSA signatures to recoverable ones.
fn to_recoverable<M>(encoder: Encoder, msg: M, signers: Vec<SignerWithSig>) -> Vec<SignerWithSig>
where
    M: AsRef<[u8]>,
{
    let recovery_transform = match encoder {
        Encoder::Abi => add_27,
        Encoder::Bcs => no_op,
        Encoder::StellarXdr => no_op,
    };
    signers
        .into_iter()
        .map(|mut signer| {
            if let Signature::Ecdsa(nonrecoverable) = signer.signature {
                signer.signature = nonrecoverable
                    .to_recoverable(msg.as_ref(), &signer.signer.pub_key, recovery_transform)
                    .map(Signature::EcdsaRecoverable)
                    .expect("failed to convert non-recoverable signature to recoverable");
            }

            signer
        })
        .collect()
}

fn add_27(recovery_byte: k256::ecdsa::RecoveryId) -> u8 {
    recovery_byte
        .to_byte()
        .checked_add(27)
        .expect("overflow when adding 27 to recovery byte")
}

fn no_op(recovery_byte: k256::ecdsa::RecoveryId) -> u8 {
    recovery_byte.to_byte()
}
