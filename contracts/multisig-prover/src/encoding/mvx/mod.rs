use bech32::FromBase32;
use cosmwasm_std::Uint256;
use multiversx_sc_codec::top_encode_to_vec_u8;
use multiversx_sc_codec::{EncodeErrorHandler, NestedEncode, NestedEncodeOutput};
use sha3::{Digest, Keccak256};

use axelar_wasm_std::hash::Hash;
use multisig::key::PublicKey;
use multisig::msg::Signer;
use multisig::verifier_set::VerifierSet;
use router_api::Message as RouterMessage;

use crate::error::ContractError;
use crate::payload::Payload;

pub mod execute_data;

#[derive(Debug)]
pub struct Message {
    pub source_chain: String,
    pub message_id: String,
    pub source_address: String,
    pub contract_address: [u8; 32],
    pub payload_hash: [u8; 32],
}

#[derive(PartialEq)]
pub struct WeightedSigner {
    pub signer: [u8; 32],
    pub weight: Vec<u8>,
}

#[derive(PartialEq)]
pub struct WeightedSigners {
    pub signers: Vec<WeightedSigner>,
    pub threshold: Vec<u8>,
    pub nonce: [u8; 32],
}

impl NestedEncode for Message {
    fn dep_encode_or_handle_err<O, H>(&self, dest: &mut O, h: H) -> Result<(), H::HandledErr>
    where
        O: NestedEncodeOutput,
        H: EncodeErrorHandler,
    {
        self.source_chain.dep_encode_or_handle_err(dest, h)?;
        self.message_id.dep_encode_or_handle_err(dest, h)?;
        self.source_address.dep_encode_or_handle_err(dest, h)?;
        self.contract_address.dep_encode_or_handle_err(dest, h)?;

        self.payload_hash.dep_encode_or_handle_err(dest, h)
    }
}

impl NestedEncode for WeightedSigner {
    fn dep_encode_or_handle_err<O, H>(&self, dest: &mut O, h: H) -> Result<(), H::HandledErr>
    where
        O: NestedEncodeOutput,
        H: EncodeErrorHandler,
    {
        self.signer.dep_encode_or_handle_err(dest, h)?;

        self.weight.dep_encode_or_handle_err(dest, h)
    }
}

impl NestedEncode for WeightedSigners {
    fn dep_encode_or_handle_err<O, H>(&self, dest: &mut O, h: H) -> Result<(), H::HandledErr>
    where
        O: NestedEncodeOutput,
        H: EncodeErrorHandler,
    {
        self.signers.dep_encode_or_handle_err(dest, h)?;
        self.threshold.dep_encode_or_handle_err(dest, h)?;

        self.nonce.dep_encode_or_handle_err(dest, h)
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

    pub fn encode(self) -> Result<Vec<u8>, ContractError> {
        Ok(
            top_encode_to_vec_u8(&(self.signers, self.threshold.as_slice(), self.nonce))
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
            nonce: Keccak256::digest(Uint256::from(verifier_set.created_at).to_be_bytes()).into(),
        }
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
    let slice_from = bytes.iter().position(|byte| *byte != 0).unwrap_or(0);

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

fn encode(payload: &Payload) -> Result<Vec<u8>, ContractError> {
    match payload {
        Payload::Messages(messages) => {
            let messages: Vec<_> = messages
                .iter()
                .map(Message::try_from)
                .collect::<Result<_, _>>()?;

            let mut result = vec![0u8];
            let mut messages =
                top_encode_to_vec_u8(&messages).expect("couldn't serialize messages as mvx");

            result.append(&mut messages);

            Ok(result)
        }
        Payload::VerifierSet(verifier_set) => {
            let mut result = vec![1u8];
            let mut weighted_signers = WeightedSigners::from(verifier_set).encode()?;

            result.append(&mut weighted_signers);

            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::{HexBinary, Uint256};

    use router_api::{CrossChainId, Message as RouterMessage};

    use crate::encoding::mvx::{uint256_to_compact_vec, WeightedSigner};
    use crate::error::ContractError;
    use crate::test::test_data::{
        curr_verifier_set, curr_verifier_set_ed25519, domain_separator_other, messages_mvx,
        verifier_set_from_pub_keys_ed25519,
    };
    use crate::{
        encoding::mvx::{payload_hash_to_sign, Message, WeightedSigners},
        payload::Payload,
    };

    #[test]
    fn weight_signers_hash() {
        let expected_hash =
            HexBinary::from_hex("839f6564c9008cfef529c02d98b5bddd6dfc34eaf1b263d57e6539575fb213a1")
                .unwrap();
        let verifier_set = curr_verifier_set_ed25519();

        assert_eq!(WeightedSigners::from(&verifier_set).hash(), expected_hash);
    }

    #[test]
    fn rotate_signers_message_hash() {
        let expected_hash =
            HexBinary::from_hex("5779af336c539091e43557568010518a91459937f4ac2a46a99f67d06d3364f8")
                .unwrap();

        let domain_separator = domain_separator_other();

        let new_pub_keys = vec![
            "8049d639e5a6980d1cd2392abcce41029cda74a1563523a202f09641cc2618f8",
            "b2a11555ce521e4944e09ab17549d85b487dcd26c84b5017a39e31a3670889ba",
            "0139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e1",
        ];
        let new_verifier_set = verifier_set_from_pub_keys_ed25519(new_pub_keys);

        let msg_to_sign = payload_hash_to_sign(
            &domain_separator,
            &curr_verifier_set_ed25519(),
            &Payload::VerifierSet(new_verifier_set),
        )
        .unwrap();
        assert_eq!(msg_to_sign, expected_hash);
    }

    #[test]
    fn router_message_to_gateway_message() {
        let source_chain = "chain0";
        let message_id = "0xff822c88807859ff226b58e24f24974a70f04b9442501ae38fd665b3c68f3834-0";
        let source_address = "0x52444f1835Adc02086c37Cb226561605e2E1699b";
        let destination_chain = "chain1";
        let destination_address = "erd1qqqqqqqqqqqqqpgqd77fnev2sthnczp2lnfx0y5jdycynjfhzzgq6p3rax";
        let payload_hash = "8c3685dc41c2eca11426f8035742fb97ea9f14931152670a5703f18fe8b392f0";

        let router_messages = RouterMessage {
            cc_id: CrossChainId {
                chain: source_chain.parse().unwrap(),
                id: message_id.parse().unwrap(),
            },
            source_address: source_address.parse().unwrap(),
            destination_address: destination_address.parse().unwrap(),
            destination_chain: destination_chain.parse().unwrap(),
            payload_hash: HexBinary::from_hex(payload_hash)
                .unwrap()
                .to_array::<32>()
                .unwrap(),
        };

        let gateway_message = Message::try_from(&router_messages).unwrap();
        assert_eq!(gateway_message.source_chain, source_chain);
        assert_eq!(gateway_message.message_id, message_id);
        assert_eq!(gateway_message.source_address, source_address);
        assert_eq!(
            gateway_message.contract_address.as_slice(),
            HexBinary::from_hex("000000000000000005006fbc99e58a82ef3c082afcd2679292693049c9371090")
                .unwrap()
                .as_slice(),
        );
        assert_eq!(
            gateway_message.payload_hash.as_slice(),
            HexBinary::from_hex(payload_hash).unwrap().as_slice()
        );
    }

    #[test]
    fn router_message_to_gateway_message_error() {
        let source_chain = "chain0";
        let message_id = "0xff822c88807859ff226b58e24f24974a70f04b9442501ae38fd665b3c68f3834-0";
        let source_address = "0x52444f1835Adc02086c37Cb226561605e2E1699b";
        let destination_chain = "chain1";
        let destination_address = "0x52444f1835Adc02086c37Cb226561605e2E1699b";
        let payload_hash = "8c3685dc41c2eca11426f8035742fb97ea9f14931152670a5703f18fe8b392f0";

        let router_messages = RouterMessage {
            cc_id: CrossChainId {
                chain: source_chain.parse().unwrap(),
                id: message_id.parse().unwrap(),
            },
            source_address: source_address.parse().unwrap(),
            destination_address: destination_address.parse().unwrap(),
            destination_chain: destination_chain.parse().unwrap(),
            payload_hash: HexBinary::from_hex(payload_hash)
                .unwrap()
                .to_array::<32>()
                .unwrap(),
        };

        let gateway_message = Message::try_from(&router_messages);

        assert!(gateway_message.is_err());
        assert_eq!(
            gateway_message.unwrap_err().to_string(),
            axelar_wasm_std::ContractError::from(ContractError::InvalidMessage {
                reason: "destination_address is not a valid MVX address: 0x52444f1835Adc02086c37Cb226561605e2E1699b".into(),
            })
            .to_string()
        );
    }

    #[test]
    fn approve_messages_hash() {
        let expected_hash =
            HexBinary::from_hex("0f9be71c5b8b7ab160552dfa59363ab4bafa2f80965822adb69595ee7d60afc7")
                .unwrap();

        let domain_separator = domain_separator_other();

        let digest = payload_hash_to_sign(
            &domain_separator,
            &curr_verifier_set_ed25519(),
            &Payload::Messages(messages_mvx()),
        )
        .unwrap();

        assert_eq!(digest, expected_hash);
    }

    #[test]
    fn signer_to_weighted_signer() {
        let verifier_set = curr_verifier_set_ed25519();
        let first_signer = verifier_set.signers.values().next().unwrap();

        let weighted_signer = WeightedSigner::from(first_signer);

        assert_eq!(
            weighted_signer.signer,
            HexBinary::from_hex("ca5b4abdf9eec1f8e2d12c187d41ddd054c81979cae9e8ee9f4ecab901cac5b6")
                .unwrap()
        );

        let mut weight = Vec::new();
        weight.push(1u8);

        assert_eq!(weighted_signer.weight, weight);
    }

    #[test]
    #[should_panic(expected = "not ed25519 key")]
    fn signer_to_weighted_signer_error() {
        let verifier_set = curr_verifier_set();
        let first_signer = verifier_set.signers.values().next().unwrap();

        let _ = WeightedSigner::from(first_signer);
    }

    #[test]
    fn test_uint256_to_compact_vec() {
        assert_eq!(
            Vec::<u8>::new(),
            uint256_to_compact_vec(Uint256::from(0u128))
        );
        assert_eq!([1].to_vec(), uint256_to_compact_vec(Uint256::from(1u128)));
        assert_eq!(
            [255].to_vec(),
            uint256_to_compact_vec(Uint256::from(u8::MAX))
        );
        assert_eq!(
            [255, 255].to_vec(),
            uint256_to_compact_vec(Uint256::from(u16::MAX))
        );
        assert_eq!(
            [255, 255, 255, 255].to_vec(),
            uint256_to_compact_vec(Uint256::from(u32::MAX))
        );
        assert_eq!(
            [255, 255, 255, 255, 255, 255, 255, 255].to_vec(),
            uint256_to_compact_vec(Uint256::from(u64::MAX))
        );
        assert_eq!(
            [255].repeat(32).to_vec(),
            uint256_to_compact_vec(Uint256::MAX)
        );
    }
}
