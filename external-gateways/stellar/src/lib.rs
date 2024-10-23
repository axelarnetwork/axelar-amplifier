pub mod error;

use std::collections::HashMap;
use std::str::FromStr;

use axelar_wasm_std::utils::TryMapExt;
use cosmwasm_std::Uint256;
use error_stack::{bail, Report, ResultExt};
use multisig::key::Signature::Ed25519;
use multisig::key::{PublicKey, Signature};
use multisig::msg::{Signer, SignerWithSig};
use multisig::verifier_set::VerifierSet;
use sha3::{Digest, Keccak256};
use stellar_strkey::Contract;
use stellar_xdr::curr::{
    BytesM, Error as XdrError, Hash, Limits, ScAddress, ScMapEntry, ScVal, StringM, VecM, WriteXdr,
};

use crate::error::Error;
use crate::error::Error::{InvalidPublicKey, InvalidSignature};

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
    pub source_chain: String,
    pub message_id: String,
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

    // Note that XDR encodes the values in sorted order by key
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

impl TryFrom<Messages> for ScVal {
    type Error = XdrError;

    fn try_from(value: Messages) -> Result<Self, XdrError> {
        let messages = value
            .0
            .iter()
            .map(|message| message.clone().try_into())
            .collect::<Result<Vec<ScVal>, _>>()?;

        Ok(ScVal::Vec(Some(VecM::try_from(messages)?.into())))
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

#[derive(Clone, Debug)]
pub enum ProofSignature {
    Signed(BytesM<64>), // Ed25519 signature
    Unsigned,
}

impl TryFrom<ProofSignature> for ScVal {
    type Error = XdrError;

    fn try_from(value: ProofSignature) -> Result<Self, XdrError> {
        let val: VecM<ScVal> = match value {
            ProofSignature::Signed(signature) => vec![
                ScVal::Symbol(StringM::from_str("Signed")?.into()),
                ScVal::Bytes(signature.to_vec().try_into()?),
            ]
            .try_into()?,

            ProofSignature::Unsigned => {
                vec![ScVal::Symbol(StringM::from_str("Unsigned")?.into())].try_into()?
            }
        };

        Ok(ScVal::Vec(Some(val.into())))
    }
}

#[derive(Clone, Debug)]
pub struct ProofSigner {
    pub signer: WeightedSigner,
    pub signature: ProofSignature,
}

impl TryFrom<ProofSigner> for ScVal {
    type Error = XdrError;

    fn try_from(value: ProofSigner) -> Result<Self, XdrError> {
        let keys: [&'static str; 2] = ["signature", "signer"];
        let vals: [ScVal; 2] = [
            value.signature.clone().try_into()?,
            value.signer.clone().try_into()?,
        ];

        sc_map_from_slices(&keys, &vals)
    }
}

impl TryFrom<(Signer, Option<Signature>)> for ProofSigner {
    type Error = Report<Error>;

    fn try_from((signer, signature): (Signer, Option<Signature>)) -> Result<Self, Self::Error> {
        let signer = WeightedSigner {
            signer: BytesM::try_from(signer.pub_key.as_ref()).change_context(InvalidPublicKey)?,
            weight: signer.weight.into(),
        };

        let signature = match signature {
            Some(Ed25519(signature)) => ProofSignature::Signed(
                BytesM::try_from(signature.to_vec()).change_context(InvalidSignature)?,
            ),
            None => ProofSignature::Unsigned,
            _ => bail!(Error::UnsupportedSignature),
        };

        Ok(Self { signer, signature })
    }
}
#[derive(Clone, Debug)]
pub struct Proof {
    pub signers: Vec<ProofSigner>,
    pub threshold: u128,
    pub nonce: BytesM<32>,
}

impl TryFrom<Proof> for ScVal {
    type Error = XdrError;

    fn try_from(value: Proof) -> Result<Self, XdrError> {
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

impl TryFrom<(VerifierSet, Vec<SignerWithSig>)> for Proof {
    type Error = Report<Error>;

    fn try_from(
        (verifier_set, signers): (VerifierSet, Vec<SignerWithSig>),
    ) -> Result<Self, Self::Error> {
        let mut signatures_by_pub_keys: HashMap<_, _> = signers
            .into_iter()
            .map(|signer| (signer.signer.pub_key.clone(), signer.signature))
            .collect();

        let mut sorted_verifiers = verifier_set.signers.into_iter().collect::<Vec<_>>();

        sorted_verifiers
            .sort_by(|(_, signer1), (_, signer2)| signer1.pub_key.cmp(&signer2.pub_key));

        let signers = sorted_verifiers
            .into_iter()
            .map(|(_, signer)| {
                let signature = signatures_by_pub_keys.remove(&signer.pub_key);
                (signer, signature)
            })
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()?;

        let nonce = Uint256::from(verifier_set.created_at)
            .to_be_bytes()
            .try_into()
            .expect("must convert from 32 bytes");

        Ok(Self {
            signers,
            threshold: verifier_set.threshold.into(),
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

    use crate::{
        CommandType, Message, Messages, Proof, ProofSignature, ProofSigner, WeightedSigner,
        WeightedSigners,
    };

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
                source_chain: format!("source-{}", i),
                message_id: format!("test-{}", i),
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
    fn weighted_signers_hash() {
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

        goldie::assert_json!(&vec![
            HexBinary::from(weighted_signers.hash().unwrap()).to_hex(),
            HexBinary::from(weighted_signers.signers_rotation_hash().unwrap()).to_hex()
        ]);
    }

    #[test]
    fn proof_signature_encode() {
        let unsigned = ScVal::try_from(ProofSignature::Unsigned)
            .unwrap()
            .to_xdr(Limits::none())
            .unwrap()
            .then(HexBinary::from)
            .to_hex();

        let signed = ScVal::try_from(ProofSignature::Signed("623ba3c98cfe635fd045b802f83471f0e8ba375aba4c8b8d03192859f5d9c1b09659807675850387c808432a3d8a894bc70e5988238ec9d2f7356eda53e468b0"
            .parse()
            .unwrap()))
            .unwrap()
            .to_xdr(Limits::none())
            .unwrap()
            .then(HexBinary::from)
            .to_hex();

        goldie::assert_json!(&vec![unsigned, signed]);
    }

    #[test]
    fn proof_signer_encode() {
        let proof_signer = ProofSigner {
            signer: WeightedSigner {
                signer: "39f771f3bd457def6c426d72c0ea3be8cacaf886845cc5eee821fb51f9af08a4".parse().unwrap(),
                weight: 8,
            },
            signature: ProofSignature::Signed("ad2086a694ce4d34ad0643a5f337f6a7d71d25dd2c516b02eb8e2c43f0d5dc72770515c8619358efbd740de68b9f62ade186e356541864dae79039ee18b4530b".parse()
                .unwrap()),
        };

        goldie::assert!(HexBinary::from(
            ScVal::try_from(proof_signer)
                .unwrap()
                .to_xdr(Limits::none())
                .unwrap()
        )
        .to_hex());
    }

    #[test]
    fn proof_encode() {
        let signers = vec![
            ("39f771f3bd457def6c426d72c0ea3be8cacaf886845cc5eee821fb51f9af08a4", 3, None),
            ("56ab9b9fa21dc37d77d093ba8d0a954ee4af43fb701e93751352876c78e9d950", 8, Some("ad2e9cf32faf4f004e7005b7a0959c65882ce66279e46f6bcd3c231e88381bb7c0b54378ec31c526af770d0abf3965c790e8b850c34521f8565eb467110d1505")),
            ("6ca711b4a5dec4c05f93ec6c61bce0b2a624f5dae358a5801b02a10404997918", 2, Some("2abbbfe5d730e8c72c0393c465c9e34c45c5745e0d72fc817cacaa2ecfd4cf00d4751e9853cac9ded1afb17d00316382fde62db962a628893e6f28985a3b3c00")),
            ("cf26fe65ca2c10ed3977d941e7f592793397bc33e549e381117bd6a199b983c7", 8, Some("c5c268c3b4ecd78984fe4579f8e421eefbea19b1a2310c5fe43f45fb338c023f808b2bd44d766b840fe5297e711f06a8a2ae7a74094a0b6abc2c92aa7a234409")),
            ("fbb4b870e800038f1379697fae3058938c59b696f38dd0fdf2659c0cf3a5b663", 1, None),
            ("fd65bd8136a40785b413624070c19677a4d42f9227c0c41624b5c63f58400668", 4, Some("c4c68ecb792f0b0509214f31ed986dad776d4f6813a0f5318c32eb14e20774a54849f4427ba1e826db3e7c39c8afb560a182ecebdb51eb41e425bd3e1cb57b08")),
            ("fe571761ad0a9834027e11e6c0a5166972054fbdd7452566e9c31f271f6caad9", 9, Some("0af1cc063353d57f3722ba93e021dc23e3498735affa2a65638bd7926f9290006df8643f75ff55c5ef55b38647464280680d5d699b588392c0188a9337afea03")),
        ].into_iter().map(|(signer, weight, signature)| ProofSigner {
            signer: WeightedSigner {
                signer: signer.parse().unwrap(),
                weight,
            },
            signature: match signature { Some(signature) => ProofSignature::Signed(signature.parse().unwrap()), None => ProofSignature::Unsigned },
        }).collect();

        let proof = Proof {
            signers,
            threshold: 21,
            nonce: "00000000000000000000000000000000000000000000000000000000000007e8"
                .parse()
                .unwrap(),
        };

        goldie::assert!(HexBinary::from(
            ScVal::try_from(proof)
                .unwrap()
                .to_xdr(Limits::none())
                .unwrap()
        )
        .to_hex());
    }
}
