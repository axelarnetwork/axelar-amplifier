pub mod execute_data;

use alloy_primitives::{Address, FixedBytes};
use bech32::FromBase32;
use cosmwasm_std::{HexBinary, Uint128, Uint256};
use multiversx_sc_codec::dep_encode_to_vec;
use multiversx_sc_codec::top_encode_to_vec_u8;
use sha3::{Digest, Keccak256};

use axelar_wasm_std::hash::Hash;
use multisig::key::PublicKey;
use multisig::msg::Signer;
use multisig::verifier_set::VerifierSet;
use router_api::Message as RouterMessage;

use crate::error::ContractError;
use crate::payload::Payload;

pub struct Message {
    pub source_chain: String,
    pub message_id: String,
    pub source_address: String,
    pub contract_address: [u8; 32],
    pub payload_hash: [u8; 32],
}

pub struct WeightedSigner {
    pub signer: [u8; 32],
    pub weight: Vec<u8>,
}

pub struct WeightedSigners {
    pub signers: Vec<WeightedSigner>,
    pub threshold: Vec<u8>,
    pub nonce: [u8; 32],
}

impl WeightedSigner {
    pub fn encode(&self) -> Result<Vec<u8>, ContractError> {
        Ok(dep_encode_to_vec(&(self.signer, self.weight.as_slice()))
            .expect("couldn't serialize weighted signer as mvx"))
    }
}

impl WeightedSigners {
    pub fn hash(&self) -> Hash {
        let mut encoded = Vec::new();

        for signer in self.signers.iter() {
            encoded.push(signer.signer.as_slice());
            encoded.push(signer.weight.as_slice());
        }

        encoded.push(self.threshold.as_slice());
        encoded.push(self.nonce.as_slice());

        Keccak256::digest(encoded.concat()).into()
    }

    pub fn encode(&self) -> Result<Vec<u8>, ContractError> {
        let signers: Vec<_> = self
            .signers
            .iter()
            .map(|signer| signer.encode())
            .collect::<Result<_, _>>()?;

        Ok(
            top_encode_to_vec_u8(&(signers, self.threshold.as_slice(), self.nonce))
                .expect("couldn't serialize weighted signers as mvx"),
        )
    }
}

impl From<&Signer> for WeightedSigner {
    fn from(signer: &Signer) -> Self {
        WeightedSigner {
            signer: ed25519_key(&signer.pub_key).expect("not ed25519 key"),
            weight: uint256_to_compact_vec(signer.weight.into()),
        }
    }
}

impl From<&VerifierSet> for WeightedSigners {
    fn from(verifier_set: &VerifierSet) -> Self {
        let mut signers = verifier_set
            .signers
            .values()
            .map(WeightedSigner::from)
            .collect::<Vec<_>>();

        signers.sort_by_key(|weighted_signer| weighted_signer.signer);

        WeightedSigners {
            signers,
            threshold: uint256_to_compact_vec(verifier_set.threshold.into()),
            nonce: Uint256::from(verifier_set.created_at).to_be_bytes(),
        }
    }
}

impl Message {
    pub fn encode(&self) -> Result<Vec<u8>, ContractError> {
        Ok(dep_encode_to_vec(&(
            self.source_chain.as_bytes(),
            self.message_id.as_bytes(),
            self.source_address.as_bytes(),
            self.contract_address,
            self.payload_hash,
        ))
        .expect("couldn't serialize message as mvx"))
    }
}

impl TryFrom<&RouterMessage> for Message {
    type Error = ContractError;

    fn try_from(msg: &RouterMessage) -> Result<Self, Self::Error> {
        let map_addr_err = |_| ContractError::InvalidMessage {
            reason: format!(
                "destination_address is not a valid MVX address: {}",
                msg.destination_address.as_str()
            ),
        };

        let (_, data, _) =
            bech32::decode(&msg.destination_address.as_str()).map_err(map_addr_err)?;
        let addr_vec = Vec::<u8>::from_base32(&data).map_err(map_addr_err)?;
        let contract_address =
            <[u8; 32]>::try_from(addr_vec).map_err(|_| ContractError::InvalidMessage {
                reason: format!(
                    "destination_address is not a valid MVX address: {}",
                    msg.destination_address.as_str()
                ),
            })?;

        Ok(Message {
            source_chain: msg.cc_id.chain.to_string(),
            message_id: msg.cc_id.id.to_string(),
            source_address: msg.source_address.to_string(),
            contract_address,
            payload_hash: msg.payload_hash,
        })
    }
}

fn uint256_to_compact_vec(value: Uint256) -> Vec<u8> {
    if value.is_zero() {
        return Vec::new();
    }

    let bytes = value.to_be_bytes();
    let mut slice_from = 0;
    for (i, byte) in bytes.iter().enumerate() {
        if *byte != 0 {
            slice_from = i;
            break;
        }
    }

    bytes[slice_from..].to_vec()
}

pub fn ed25519_key(pub_key: &PublicKey) -> Result<[u8; 32], ContractError> {
    match pub_key {
        PublicKey::Ed25519(ed25519_key) => {
            return Ok(<[u8; 32]>::try_from(ed25519_key.as_ref())
                .expect("couldn't convert pubkey to ed25519 public key"));
        }
        _ => {
            return Err(ContractError::InvalidPublicKey {
                reason: "Public key is not ed25519".into(),
            })
        }
    }
}

pub fn payload_hash_to_sign(
    domain_separator: &Hash,
    signer: &VerifierSet,
    payload: &Payload,
) -> Result<Hash, ContractError> {
    let signer_hash = WeightedSigners::from(signer).hash();
    let data_hash = Keccak256::digest(encode(payload)?);

    let unsigned = [
        "\x19MultiversX Signed Message:\n".as_bytes(),
        domain_separator,
        signer_hash.as_slice(),
        data_hash.as_slice(),
    ]
    .concat();

    Ok(Keccak256::digest(unsigned).into())
}

pub fn encode(payload: &Payload) -> Result<Vec<u8>, ContractError> {
    match payload {
        Payload::Messages(messages) => {
            let messages: Vec<_> = messages
                .iter()
                .map(Message::try_from)
                .collect::<Result<_, _>>()?;

            let messages: Vec<_> = messages
                .iter()
                .map(|message| message.encode())
                .collect::<Result<_, _>>()?;

            Ok(top_encode_to_vec_u8(&([0u8], messages))
                .expect("couldn't serialize messages as mvx")
                .into())
        }
        Payload::VerifierSet(verifier_set) => {
            let weighted_signers = WeightedSigners::from(verifier_set).encode()?;

            Ok(top_encode_to_vec_u8(&([1u8], weighted_signers))
                .expect("couldn't serialize messages as mvx")
                .into())
        }
    }
}
