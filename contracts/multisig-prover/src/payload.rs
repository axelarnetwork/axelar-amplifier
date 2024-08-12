use axelar_wasm_std::hash::Hash;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{from_json, HexBinary, StdResult};
use cw_storage_plus::{Key, KeyDeserialize, PrimaryKey};
use error_stack::Result;
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;
use router_api::{CrossChainId, Message};
use sha3::{Digest, Keccak256};

use crate::encoding::{
        abi,
        rkyv::{self, to_verifier_set},
        Encoder,
    };
use crate::error::ContractError;

#[cw_serde]
pub enum Payload {
    Messages(Vec<Message>),
    VerifierSet(VerifierSet),
}

impl Payload {
    /// id returns the unique identifier for the payload, which can be either
    /// - the hash of comma separated sorted message ids
    /// - the hash of the verifier set
    pub fn id(&self) -> PayloadId {
        match self {
            Payload::Messages(msgs) => {
                let message_ids: Vec<_> = msgs.iter().map(|msg| msg.cc_id.clone()).collect();

                message_ids.as_slice().into()
            }
            Payload::VerifierSet(verifier_set) => verifier_set.hash().as_slice().into(),
        }
    }

    pub fn digest(
        &self,
        encoder: Encoder,
        domain_separator: &Hash,
        cur_verifier_set: &VerifierSet,
    ) -> Result<Hash, ContractError> {
        match encoder {
            Encoder::Abi => abi::payload_hash_to_sign(domain_separator, cur_verifier_set, self),
            Encoder::Bcs => todo!(),
            Encoder::Rkyv => Ok(axelar_rkyv_encoding::hash_payload(
                &domain_separator,
                &to_verifier_set(cur_verifier_set)?,
                &axelar_rkyv_encoding::types::Payload::try_from(self)?,
                axelar_rkyv_encoding::hasher::generic::Keccak256Hasher::default(),
            )),
        }
    }

    pub fn message_ids(&self) -> Option<Vec<CrossChainId>> {
        match &self {
            Payload::Messages(msgs) => Some(msgs.iter().map(|msg| msg.cc_id.clone()).collect()),
            Payload::VerifierSet(_) => None,
        }
    }

    pub fn execute_data(
        &self,
        encoder: Encoder,
        domain_separator: &Hash,
        verifier_set: &VerifierSet,
        signers_with_sigs: Vec<SignerWithSig>,
        payload: &Payload,
    ) -> Result<HexBinary, ContractError> {
        let payload_hash = payload.digest(encoder, domain_separator, verifier_set)?;

        match encoder {
            Encoder::Abi => {
                abi::execute_data::encode(verifier_set, signers_with_sigs, &payload_hash, payload)
            }
            Encoder::Bcs => todo!(),
            Encoder::Rkyv => Ok(rkyv::encode(
                signers_with_sigs,
                payload_hash,
                verifier_set,
                payload,
            )?),
        }
    }
}

#[cw_serde]
pub struct PayloadId(HexBinary);

impl From<&[u8]> for PayloadId {
    fn from(id: &[u8]) -> Self {
        Self(id.into())
    }
}

impl<'a> PrimaryKey<'a> for PayloadId {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = PayloadId;
    type SuperSuffix = PayloadId;

    fn key(&self) -> Vec<Key> {
        vec![Key::Ref(self.0.as_slice())]
    }
}

impl KeyDeserialize for PayloadId {
    type Output = PayloadId;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        Ok(from_json(value).expect("violated invariant: PayloadId is not deserializable"))
    }
}

impl From<&[CrossChainId]> for PayloadId {
    fn from(ids: &[CrossChainId]) -> Self {
        let mut message_ids = ids.iter().map(|id| id.to_string()).collect::<Vec<_>>();
        message_ids.sort();

        Keccak256::digest(message_ids.join(",")).as_slice().into()
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use axelar_rkyv_encoding::types::{ArchivedExecuteData, ArchivedSignature};
    use cosmwasm_std::Uint128;
    use multisig::{
        key::{Recoverable, Signature},
        msg::Signer,
    };
    use router_api::{Address, ChainName, ChainNameRaw, CrossChainId};

    use crate::payload::PayloadId;
    use crate::test::test_data;

    #[test]
    fn test_payload_id() {
        let messages = test_data::messages();
        let mut message_ids: Vec<CrossChainId> =
            messages.into_iter().map(|msg| msg.cc_id).collect();

        let res: PayloadId = message_ids.as_slice().into();

        message_ids.reverse();
        let res2: PayloadId = message_ids.as_slice().into();

        assert_eq!(res, res2);
    }

    #[test]
    fn rkyv_message_encoding_works_as_expected() {
        let message = Message {
            cc_id: CrossChainId {
                source_chain: ChainNameRaw::from_str("fantom").unwrap(),
                message_id: "123".to_string().parse().unwrap(),
            },
            source_address: Address::from_str("aabbbccc").unwrap(),
            destination_chain: ChainName::from_str("solana").unwrap(),
            destination_address: Address::from_str("aabbbccc").unwrap(),
            payload_hash: [42; 32],
        };
        let messages = vec![message.clone()];
        let payload = Payload::Messages(messages);
        let encoder = Encoder::Rkyv;
        let domain_separator = [123; 32];
        let raw_public_key = [55; 33];
        let signer = Signer {
            address: cosmwasm_std::Addr::unchecked("foobar"),
            weight: Uint128::one(),
            pub_key: multisig::key::PublicKey::Ecdsa(
                HexBinary::from_hex(hex::encode(raw_public_key).as_str()).unwrap(),
            ),
        };
        let signers = [(signer.address.clone().to_string(), signer.clone())]
            .to_vec()
            .into_iter()
            .collect();
        let threshold = 1_u128;
        let created_at = 500;
        let verifier_set = VerifierSet {
            signers,
            threshold: Uint128::from(threshold),
            created_at,
        };
        let raw_signature = [55; 65];
        let signature = HexBinary::from_hex(hex::encode(raw_signature).as_str()).unwrap();
        let signature = Signature::EcdsaRecoverable(Recoverable::try_from(signature).unwrap());
        let signers_with_sigs = vec![SignerWithSig {
            signer: signer.clone(),
            signature,
        }];
        let digest_hash = payload
            .digest(encoder.clone(), &domain_separator, &verifier_set)
            .unwrap();
        let encoded_archive_payload = payload
            .execute_data(
                encoder,
                &domain_separator,
                &verifier_set,
                signers_with_sigs,
                &payload,
            )
            .unwrap();

        // now we decode and see what happens
        let archived_data =
            ArchivedExecuteData::from_bytes(encoded_archive_payload.as_slice()).unwrap();

        // assert messages
        let messages = archived_data.messages().unwrap();
        assert_eq!(messages.len(), 1);
        let archived_message = messages.get(0).unwrap();
        assert_eq!(archived_message.cc_id().id(), message.cc_id.message_id.to_string());
        assert_eq!(
            archived_message.cc_id().chain(),
            message.cc_id.source_chain.to_string()
        );

        // assert signers
        let proof = archived_data.proof();
        dbg!(&proof.threshold);
        dbg!(&threshold.to_ne_bytes());
        assert_eq!(proof.threshold.maybe_u128().unwrap(), threshold);
        assert_eq!(proof.nonce, created_at);
        assert_eq!(proof.signers_with_signatures.len(), 1);
        let (archived_signer_public_key, archived_signer) =
            proof.signers_with_signatures.iter().next().unwrap();
        let pk_bytes = archived_signer_public_key.to_bytes();
        assert_eq!(pk_bytes.as_slice(), signer.pub_key.as_ref());
        assert_eq!(archived_signer.weight.maybe_u128().unwrap(), 1);
        let ArchivedSignature::EcdsaRecoverable(archived_signature) =
            archived_signer.signature.as_ref().unwrap()
        else {
            panic!("")
        };
        assert_eq!(*archived_signature, raw_signature);

        // assert thashes match
        let mut bytes = [0; 32];
        bytes[0] = 1;
        let u256_thereshold = axelar_rkyv_encoding::types::U256::from_le(bytes);
        let rky_public_key = axelar_rkyv_encoding::types::PublicKey::new_ecdsa(raw_public_key);
        let signers = [(rky_public_key, u256_thereshold.clone())]
            .into_iter()
            .collect();
        let vs =
            axelar_rkyv_encoding::types::VerifierSet::new(created_at, signers, u256_thereshold);
        let archived_hash = archived_data.hash_payload_for_verifier_set(
            &domain_separator,
            &vs,
            axelar_rkyv_encoding::hasher::generic::Keccak256Hasher::default(),
        );
        assert_eq!(archived_hash, digest_hash)
    }
}
