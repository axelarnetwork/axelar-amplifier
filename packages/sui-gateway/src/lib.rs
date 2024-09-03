use std::str::FromStr;

use cosmwasm_std::Uint256;
use error_stack::{report, Report, ResultExt};
use multisig::key::PublicKey;
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use sui_types::SuiAddress;

pub mod error;
pub mod events;

use error::Error;

#[repr(u8)]
pub enum CommandType {
    ApproveMessages = 0,
    RotateSigners = 1,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Bytes32 {
    bytes: [u8; 32],
}

impl AsRef<[u8]> for Bytes32 {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<[u8; 32]> for Bytes32 {
    fn from(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WeightedSigner {
    pub pub_key: Vec<u8>,
    pub weight: u128,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WeightedSigners {
    pub signers: Vec<WeightedSigner>,
    pub threshold: u128,
    pub nonce: Bytes32,
}

impl TryFrom<VerifierSet> for WeightedSigners {
    type Error = Report<Error>;

    fn try_from(verifier_set: VerifierSet) -> Result<Self, Self::Error> {
        let mut signers = verifier_set
            .signers
            .values()
            .map(|signer| match &signer.pub_key {
                PublicKey::Ecdsa(key) => Ok(WeightedSigner {
                    pub_key: key.to_vec(),
                    weight: signer.weight.into(),
                }),
                PublicKey::Ed25519(_) => Err(Report::new(Error::UnsupportedPublicKey)),
            })
            .collect::<Result<Vec<_>, _>>()?;
        signers.sort_by(|signer1, signer2| signer1.pub_key.cmp(&signer2.pub_key));

        let nonce = Uint256::from(verifier_set.created_at).to_be_bytes().into();

        Ok(Self {
            signers,
            threshold: verifier_set.threshold.into(),
            nonce,
        })
    }
}

impl WeightedSigners {
    pub fn hash(&self) -> [u8; 32] {
        let hash =
            Keccak256::digest(bcs::to_bytes(&self).expect("failed to serialize WeightedSigners"));

        hash.into()
    }
}

#[derive(Serialize)]
pub struct MessageToSign {
    pub domain_separator: Bytes32,
    pub signers_hash: Bytes32,
    pub data_hash: Bytes32,
}

impl MessageToSign {
    pub fn hash(&self) -> [u8; 32] {
        let hash =
            Keccak256::digest(bcs::to_bytes(&self).expect("failed to serialize MessageToSign"));

        hash.into()
    }
}

#[derive(Serialize)]
pub struct Message {
    source_chain: String,
    message_id: String,
    source_address: String,
    destination_id: SuiAddress,
    payload_hash: Bytes32,
}

impl TryFrom<&router_api::Message> for Message {
    type Error = Report<Error>;

    fn try_from(value: &router_api::Message) -> Result<Self, Self::Error> {
        Ok(Self {
            source_chain: value.cc_id.source_chain.to_string(),
            message_id: value.cc_id.message_id.to_string(),
            source_address: value.source_address.to_string(),
            destination_id: SuiAddress::from_str(&value.destination_address)
                .change_context(Error::InvalidAddress(value.destination_address.to_string()))?,
            payload_hash: value.payload_hash.into(),
        })
    }
}

#[derive(Serialize)]
pub struct Signature {
    bytes: Vec<u8>,
}

impl TryFrom<multisig::key::Signature> for Signature {
    type Error = Report<Error>;

    fn try_from(signature: multisig::key::Signature) -> Result<Self, Self::Error> {
        match signature {
            // The move contracts require recoverable signatures. This should
            // only be called after the proper conversion during encoding.
            multisig::key::Signature::EcdsaRecoverable(signature) => Ok(Self {
                bytes: signature.as_ref().to_vec(),
            }),
            _ => Err(report!(Error::UnsupportedSignature)),
        }
    }
}

#[derive(Serialize)]
pub struct Proof {
    signers: WeightedSigners,
    signatures: Vec<Signature>,
}

impl TryFrom<(VerifierSet, Vec<SignerWithSig>)> for Proof {
    type Error = Report<Error>;

    fn try_from(
        (verifier_set, mut signatures): (VerifierSet, Vec<SignerWithSig>),
    ) -> Result<Self, Self::Error> {
        signatures.sort_by(|signer1, signer2| signer1.signer.pub_key.cmp(&signer2.signer.pub_key));

        Ok(Self {
            signers: verifier_set.try_into()?,
            signatures: signatures
                .into_iter()
                .map(|signer| signer.signature)
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct ExecuteData {
    pub payload: Vec<u8>,
    pub proof: Vec<u8>,
}

impl ExecuteData {
    pub fn new(payload: Vec<u8>, proof: Vec<u8>) -> Self {
        Self { payload, proof }
    }
}
