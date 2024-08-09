use cosmwasm_schema::cw_serde;
use cosmwasm_std::{from_json, HexBinary, StdResult};
use cw_storage_plus::{Key, KeyDeserialize, PrimaryKey};
use multisig::verifier_set::VerifierSet;
use router_api::{CrossChainId, Message, FIELD_DELIMITER};
use sha3::{Digest, Keccak256};

#[cw_serde]
pub enum Payload {
    Messages(Vec<Message>),
    VerifierSet(VerifierSet),
}

impl Payload {
    /// id returns the unique identifier for the payload, which can be either
    /// - Hash of 0 followed by '_' separated message ids
    /// - Hash of 1 followed by the verifier set hash
    pub fn id(&self) -> PayloadId {
        let hash = match self {
            Payload::Messages(msgs) => {
                let message_ids: Vec<String> =
                    msgs.iter().map(|msg| msg.cc_id.to_string()).collect();

                message_ids.join(&FIELD_DELIMITER.to_string()).into()
            }
            Payload::VerifierSet(verifier_set) => verifier_set.hash().to_vec(),
        };

        let mut id = vec![self.variant_to_u8()];
        id.extend(hash);

        Keccak256::digest(id).to_vec().into()
    }

    fn variant_to_u8(&self) -> u8 {
        match self {
            Payload::Messages(_) => 0,
            Payload::VerifierSet(_) => 1,
        }
    }

    pub fn message_ids(&self) -> Option<Vec<CrossChainId>> {
        match &self {
            Payload::Messages(msgs) => Some(msgs.iter().map(|msg| msg.cc_id.clone()).collect()),
            Payload::VerifierSet(_) => None,
        }
    }
}

#[cw_serde]
pub struct PayloadId(HexBinary);

impl From<Vec<u8>> for PayloadId {
    fn from(id: Vec<u8>) -> Self {
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

#[cfg(test)]
mod test {
    use crate::payload::Payload;
    use crate::test::test_data;

    #[test]
    fn payload_messages_id_unchanged() {
        let payload = Payload::Messages(test_data::messages());

        goldie::assert_json!(payload.id());
    }

    #[test]
    fn payload_verifier_set_id_unchanged() {
        let payload = Payload::VerifierSet(test_data::curr_verifier_set());

        goldie::assert_json!(payload.id());
    }
}
