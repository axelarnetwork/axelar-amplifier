pub mod error;

use std::str::FromStr;

use axelar_wasm_std::utils::TryMapExt;
use cosmwasm_std::Uint256;
use error_stack::{Report, ResultExt};
use multisig::key::PublicKey;
use multisig::verifier_set::VerifierSet;
use sha3::{Digest, Keccak256};
use stellar_strkey::Contract;
use stellar_xdr::curr::{
    BytesM, Error as XdrError, Hash, Limits, ScAddress, ScMapEntry, ScVal, StringM, VecM, WriteXdr,
};

use crate::error::Error;

#[derive(Debug, Clone)]
pub enum CommandType {
    ApproveMessages,
    RotateSigners,
}

impl CommandType {
    pub fn as_str(&self) -> &'static str {
        match self {
            CommandType::ApproveMessages => "ApproveMessages",
            CommandType::RotateSigners => "RotateSigners",
        }
    }
}

impl TryFrom<CommandType> for ScVal {
    type Error = XdrError;

    fn try_from(value: CommandType) -> Result<Self, XdrError> {
        let val: VecM<ScVal> =
            vec![ScVal::Symbol(StringM::from_str(value.as_str())?.into())].try_into()?;

        Ok(ScVal::Vec(Some(val.into())))
    }
}

#[derive(Debug, Clone)]
pub struct Message {
    pub message_id: String,
    pub source_chain: String,
    pub source_address: String,
    pub contract_address: Contract,
    pub payload_hash: Hash,
}

impl TryFrom<&router_api::Message> for Message {
    type Error = Report<Error>;

    fn try_from(value: &router_api::Message) -> Result<Self, Self::Error> {
        Ok(Self {
            source_chain: value.cc_id.source_chain.to_string(),
            message_id: value.cc_id.message_id.to_string(),
            source_address: value.source_address.to_string(),
            contract_address: Contract::from_string(value.destination_address.as_str())
                .change_context(Error::InvalidDestinationAddress)
                .attach_printable(value.destination_address.to_string())?,
            payload_hash: value.payload_hash.into(),
        })
    }
}

impl TryFrom<Message> for ScVal {
    type Error = XdrError;

    fn try_from(value: Message) -> Result<Self, XdrError> {
        let keys: [&'static str; 5] = [
            "contract_address",
            "message_id",
            "payload_hash",
            "source_address",
            "source_chain",
        ];

        let vals: [ScVal; 5] = [
            ScVal::Address(ScAddress::Contract(Hash(value.contract_address.0))),
            ScVal::String(StringM::from_str(&value.message_id)?.into()),
            ScVal::Bytes(BytesM::try_from(AsRef::<[u8; 32]>::as_ref(&value.payload_hash))?.into()),
            ScVal::String(StringM::from_str(&value.source_address)?.into()),
            ScVal::String(StringM::from_str(&value.source_chain)?.into()),
        ];

        sc_map_from_slices(&keys, &vals)
    }
}

pub struct Messages(Vec<Message>);

impl From<Vec<Message>> for Messages {
    fn from(v: Vec<Message>) -> Self {
        Messages(v)
    }
}

impl Messages {
    pub fn messages_approval_hash(&self) -> Result<[u8; 32], XdrError> {
        let messages = self
            .0
            .iter()
            .map(|message| message.clone().try_into())
            .collect::<Result<Vec<ScVal>, _>>()?;

        let val: ScVal = (CommandType::ApproveMessages, messages)
            .try_into()
            .expect("must convert tuple of size 2 to ScVec");

        let hash = Keccak256::digest(val.to_xdr(Limits::none())?);

        Ok(hash.into())
    }
}

#[derive(Clone, Debug)]
pub struct WeightedSigner {
    pub signer: BytesM<32>,
    pub weight: u128,
}

impl TryFrom<WeightedSigner> for ScVal {
    type Error = XdrError;

    fn try_from(value: WeightedSigner) -> Result<Self, XdrError> {
        let keys: [&'static str; 2] = ["signer", "weight"];

        let vals: [ScVal; 2] = [
            ScVal::Bytes(value.signer.to_vec().try_into()?),
            value.weight.into(),
        ];

        sc_map_from_slices(&keys, &vals)
    }
}

#[derive(Debug, Clone)]
pub struct WeightedSigners {
    pub signers: Vec<WeightedSigner>,
    pub threshold: u128,
    pub nonce: BytesM<32>,
}

impl WeightedSigners {
    pub fn hash(&self) -> Result<[u8; 32], XdrError> {
        let val: ScVal = self.clone().try_into()?;
        let hash = Keccak256::digest(val.to_xdr(Limits::none())?);

        Ok(hash.into())
    }

    pub fn signers_rotation_hash(&self) -> Result<[u8; 32], XdrError> {
        let val: ScVal = (CommandType::RotateSigners, self.clone())
            .try_into()
            .expect("must convert tuple of size 2 to ScVec");

        let hash = Keccak256::digest(val.to_xdr(Limits::none())?);

        Ok(hash.into())
    }
}

impl TryFrom<WeightedSigners> for ScVal {
    type Error = XdrError;

    fn try_from(value: WeightedSigners) -> Result<Self, XdrError> {
        let signers = value.signers.clone().try_map(|signer| signer.try_into())?;

        let keys: [&'static str; 3] = ["nonce", "signers", "threshold"];

        let vals: [ScVal; 3] = [
            ScVal::Bytes(value.nonce.to_vec().try_into()?),
            ScVal::Vec(Some(signers.try_into()?)),
            value.threshold.into(),
        ];

        sc_map_from_slices(&keys, &vals)
    }
}

impl TryFrom<&VerifierSet> for WeightedSigners {
    type Error = Report<Error>;

    fn try_from(value: &VerifierSet) -> Result<Self, Self::Error> {
        let mut signers = value
            .signers
            .values()
            .map(|signer| match &signer.pub_key {
                PublicKey::Ed25519(key) => Ok(WeightedSigner {
                    signer: BytesM::try_from(key.as_ref())
                        .change_context(Error::InvalidPublicKey)
                        .attach_printable(key.to_hex())?,
                    weight: signer.weight.into(),
                }),
                PublicKey::Ecdsa(_) => Err(Report::new(Error::UnsupportedPublicKey)),
            })
            .collect::<Result<Vec<_>, _>>()?;

        signers.sort_by(|signer1, signer2| signer1.signer.cmp(&signer2.signer));

        let nonce = Uint256::from(value.created_at)
            .to_be_bytes()
            .try_into()
            .expect("must convert from 32 bytes");

        Ok(Self {
            signers,
            threshold: value.threshold.into(),
            nonce,
        })
    }
}

/// Form a new Map from a slice of symbol-names and a slice of values. Keys must be in sorted order.
fn sc_map_from_slices(keys: &[&str], vals: &[ScVal]) -> Result<ScVal, XdrError> {
    let vec: VecM<ScMapEntry> = keys
        .iter()
        .zip(vals.iter())
        .map(|(key, val)| {
            Ok(ScMapEntry {
                key: ScVal::Symbol(StringM::from_str(key)?.into()),
                val: val.clone(),
            })
        })
        .collect::<Result<Vec<_>, XdrError>>()?
        .try_into()?;

    Ok(ScVal::Map(Some(vec.into())))
}

#[cfg(test)]
mod test {
    use axelar_wasm_std::FnExt;
    use cosmwasm_std::HexBinary;
    use serde::Serialize;
    use stellar_xdr::curr::{Limits, ScVal, WriteXdr};

    use crate::{CommandType, Message, Messages, WeightedSigner, WeightedSigners};

    #[test]
    fn command_type_encode() {
        #[derive(Serialize)]
        struct Encoded {
            approve_messages: String,
            rotate_signers: String,
        }
        let approve_messages = ScVal::try_from(CommandType::ApproveMessages)
            .unwrap()
            .to_xdr(Limits::none())
            .unwrap()
            .then(HexBinary::from)
            .to_hex();
        let rotate_signers = ScVal::try_from(CommandType::RotateSigners)
            .unwrap()
            .to_xdr(Limits::none())
            .unwrap()
            .then(HexBinary::from)
            .to_hex();

        let encoded = Encoded {
            approve_messages,
            rotate_signers,
        };

        goldie::assert_json!(&encoded);
    }

    #[test]
    fn messages_approval_hash() {
        let payload_hashes = [
            "cfa347779c9b646ddf628c4da721976ceb998f1ab2c097b52e66a575c3975a6c",
            "fb5eb8245e3b8eb9d44f228ee142a3378f57d49fc95fa78d437ff8aa5dd564ba",
            "90e3761c0794fbbd8b563a0d05d83395e7f88f64f30eebb7c5533329f6653e84",
            "60e146cb9c548ba6e614a87910d8172c9d21279a3f8f4da256ff36e15b80ea30",
        ];

        let messages: Messages = (1..=4)
            .map(|i| Message {
                message_id: format!("test-{}", i),
                source_chain: format!("source-{}", i),
                source_address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHK3M"
                    .to_string(),
                contract_address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMDR4"
                    .parse()
                    .unwrap(),
                payload_hash: payload_hashes[i - 1].parse().expect("invalid hash"),
            })
            .collect::<Vec<_>>()
            .into();
        goldie::assert!(HexBinary::from(messages.messages_approval_hash().unwrap()).to_hex());
    }

    #[test]
    fn signers_rotation_hash() {
        let weighted_signers = WeightedSigners {
            signers: vec![
                WeightedSigner {
                    signer: "0a245a2a2a5e8ec439d1377579a08fc78ea55647ba6fcb1f5d8a360218e8a985"
                        .parse()
                        .unwrap(),
                    weight: 3,
                },
                WeightedSigner {
                    signer: "0b422cf449d900f6f8eb97f62e35811c62eb75feb84dfccef44a5c1c3dbac2ad"
                        .parse()
                        .unwrap(),
                    weight: 2,
                },
                WeightedSigner {
                    signer: "18c34bf01a11b5ba21ea11b1678f3035ef753f0bdb1d5014ec21037e8f99e2a2"
                        .parse()
                        .unwrap(),
                    weight: 4,
                },
                WeightedSigner {
                    signer: "f683ca8a6d7fe55f25599bb64b01edcc5eeb85fe5b63d3a4f0b3c32405005518"
                        .parse()
                        .unwrap(),
                    weight: 4,
                },
                WeightedSigner {
                    signer: "fbb4b870e800038f1379697fae3058938c59b696f38dd0fdf2659c0cf3a5b663"
                        .parse()
                        .unwrap(),
                    weight: 2,
                },
            ],
            threshold: 8,
            nonce: "8784bf7be5a9baaeea47e12d9e8ad0dec29afcbc3617d97f771e3c24fa945dce"
                .parse()
                .unwrap(),
        };

        goldie::assert!(
            HexBinary::from(weighted_signers.signers_rotation_hash().unwrap()).to_hex()
        );
    }
}
