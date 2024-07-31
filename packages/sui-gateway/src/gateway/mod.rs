use cosmwasm_std::HexBinary;
use error_stack::Report;
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::base_types::SuiAddress;
use crate::error::Error;

pub mod events;

pub const COMMAND_TYPE_APPROVE_MESSAGES: u8 = 0;
pub const COMMAND_TYPE_ROTATE_SIGNERS: u8 = 1;

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

impl From<VerifierSet> for WeightedSigners {
    fn from(verifier_set: VerifierSet) -> Self {
        let mut signers: Vec<_> = verifier_set
            .signers
            .values()
            .map(|signer| WeightedSigner {
                pub_key: HexBinary::from(signer.pub_key.clone()).to_vec(),
                weight: signer.weight.into(),
            })
            .collect();
        signers.sort_by_key(|signer| signer.pub_key.clone());

        let nonce = [0u8; 24]
            .into_iter()
            .chain(verifier_set.created_at.to_be_bytes())
            .collect::<Vec<_>>();

        Self {
            signers,
            threshold: verifier_set.threshold.into(),
            nonce: <[u8; 32]>::try_from(nonce)
                .expect("nonce must be 32 bytes")
                .into(),
        }
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
            destination_id: value.destination_address.parse()?,
            payload_hash: value.payload_hash.into(),
        })
    }
}

#[derive(Serialize)]
pub struct Signature {
    bytes: Vec<u8>,
}

impl From<multisig::key::Signature> for Signature {
    fn from(signature: multisig::key::Signature) -> Self {
        Self {
            bytes: signature.as_ref().to_vec(),
        }
    }
}

#[derive(Serialize)]
pub struct Proof {
    signers: WeightedSigners,
    signatures: Vec<Signature>,
}

impl From<(VerifierSet, Vec<SignerWithSig>)> for Proof {
    fn from((verifier_set, mut signatures): (VerifierSet, Vec<SignerWithSig>)) -> Self {
        signatures.sort_by_key(|signer| signer.signer.pub_key.clone());

        Self {
            signers: verifier_set.into(),
            signatures: signatures
                .into_iter()
                .map(|signer| signer.signature)
                .map(Into::into)
                .collect(),
        }
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
