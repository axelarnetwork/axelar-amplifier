use axelar_wasm_std::hash::Hash;
use clarity::types::StacksEpochId;
use clarity::vm::types::{
    BufferLength, ListTypeData, SequenceSubtype, TupleData, TupleTypeSignature, TypeSignature,
};
use clarity::vm::{ClarityName, Value};
use cosmwasm_std::Uint256;
use error_stack::{Report, ResultExt};
use multisig::key::PublicKey;
use multisig::msg::Signer;
use multisig::verifier_set::VerifierSet;
use sha3::{Digest, Keccak256};

use crate::stacks::error::Error;

mod error;
pub(crate) mod http_client;
mod its_verifier;
pub(crate) mod verifier;

pub struct WeightedSigner {
    pub signer: Vec<u8>,
    pub weight: u128,
}

pub struct WeightedSigners {
    pub signers: Vec<WeightedSigner>,
    pub threshold: Value,
    pub nonce: Value,
}

impl TryFrom<&Signer> for WeightedSigner {
    type Error = Error;

    fn try_from(signer: &Signer) -> Result<Self, Error> {
        Ok(WeightedSigner {
            signer: ecdsa_key(&signer.pub_key)?,
            weight: signer.weight.into(),
        })
    }
}

impl TryFrom<&VerifierSet> for WeightedSigners {
    type Error = Report<Error>;

    fn try_from(verifier_set: &VerifierSet) -> Result<Self, Self::Error> {
        let mut signers: Vec<WeightedSigner> = verifier_set
            .signers
            .values()
            .map(WeightedSigner::try_from)
            .collect::<Result<_, _>>()?;

        signers.sort_by(|signer1, signer2| signer1.signer.cmp(&signer2.signer));

        Ok(WeightedSigners {
            signers,
            threshold: Value::UInt(verifier_set.threshold.into()),
            nonce: Value::buff_from(
                Uint256::from(verifier_set.created_at)
                    .to_be_bytes()
                    .to_vec(),
            )
            .change_context(Error::InvalidEncoding)?,
        })
    }
}

impl WeightedSigner {
    fn try_into_value(self) -> Result<Value, Report<Error>> {
        Ok(Value::from(
            TupleData::from_data(vec![
                (
                    ClarityName::from("signer"),
                    Value::buff_from(self.signer).change_context(Error::InvalidEncoding)?,
                ),
                (ClarityName::from("weight"), Value::UInt(self.weight)),
            ])
            .change_context(Error::InvalidEncoding)?,
        ))
    }
}

impl WeightedSigners {
    pub fn hash(self) -> Result<Hash, Report<Error>> {
        let value = self
            .try_into_value()
            .change_context(Error::InvalidEncoding)?;

        Ok(Keccak256::digest(
            value
                .serialize_to_vec()
                .map_err(|_| Error::InvalidEncoding)?,
        )
        .into())
    }

    pub fn try_into_value(self) -> Result<Value, Report<Error>> {
        let weighted_signers: Vec<Value> = self
            .signers
            .into_iter()
            .map(|weighted_signer| weighted_signer.try_into_value())
            .collect::<Result<_, _>>()
            .change_context(Error::InvalidEncoding)?;

        let signer_type_signature = TupleTypeSignature::try_from(vec![
            (
                ClarityName::from("signer"),
                TypeSignature::SequenceType(SequenceSubtype::BufferType(
                    BufferLength::try_from(33u32).change_context(Error::InvalidEncoding)?,
                )),
            ),
            (ClarityName::from("weight"), TypeSignature::UIntType),
        ])
        .change_context(Error::InvalidEncoding)?;

        let tuple_data = TupleData::from_data(vec![
            (
                ClarityName::from("signers"),
                Value::list_with_type(
                    &StacksEpochId::latest(),
                    weighted_signers,
                    ListTypeData::new_list(TypeSignature::from(signer_type_signature), 100)
                        .change_context(Error::InvalidEncoding)?,
                )
                .map_err(|_| Error::InvalidEncoding)?,
            ),
            (ClarityName::from("threshold"), self.threshold),
            (ClarityName::from("nonce"), self.nonce),
        ])
        .change_context(Error::InvalidEncoding)?;

        Ok(Value::from(tuple_data))
    }
}

pub fn ecdsa_key(pub_key: &PublicKey) -> Result<Vec<u8>, Error> {
    match pub_key {
        PublicKey::Ecdsa(ecdsa_key) => Ok(ecdsa_key.to_vec()),
        _ => Err(Error::NotEcdsaKey),
    }
}
