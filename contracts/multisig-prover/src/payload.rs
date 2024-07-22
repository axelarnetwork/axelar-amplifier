use axelar_wasm_std::hash::Hash;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{from_json, HexBinary, StdResult};
use cw_storage_plus::{Key, KeyDeserialize, PrimaryKey};
use error_stack::Result;
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;
use router_api::{CrossChainId, Message};
use sha3::{Digest, Keccak256};

use crate::encoding::{abi, Encoder};
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
                let message_ids = msgs
                    .iter()
                    .map(|msg| msg.cc_id.clone())
                    .collect::<Vec<CrossChainId>>();

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
    use router_api::CrossChainId;

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
}
