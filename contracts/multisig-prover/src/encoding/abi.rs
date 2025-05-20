use axelar_wasm_std::hash::Hash;
use cosmwasm_std::HexBinary;
use error_stack::{Result, ResultExt};
use ethers_contract::contract::EthCall;
use ethers_core::abi::{encode as abi_encode, Token, Tokenize};
use evm_gateway::{
    ApproveMessagesCall, CommandType, Message, Proof, RotateSignersCall, WeightedSigners,
};
use itertools::Itertools;
use k256::ecdsa::RecoveryId;
use multisig::{Signature, SignerWithSig, VerifierSet};
use sha3::{Digest, Keccak256};

use crate::error::ContractError;
use crate::Payload;

const PREFIX: &str = "\x19Ethereum Signed Message:\n96";

impl From<&Payload> for CommandType {
    fn from(payload: &Payload) -> Self {
        match payload {
            Payload::Messages(_) => CommandType::ApproveMessages,
            Payload::VerifierSet(_) => CommandType::RotateSigners,
        }
    }
}

pub fn payload_digest(
    domain_separator: &Hash,
    signer: &VerifierSet,
    payload: &Payload,
) -> Result<Hash, ContractError> {
    let signer_hash = WeightedSigners::try_from(signer)
        .map(|signers| signers.hash())
        .change_context(ContractError::InvalidVerifierSet)?;

    let data_hash = Keccak256::digest(encode_payload(payload)?);

    // Prefix for standard EVM signed data https://eips.ethereum.org/EIPS/eip-191
    let unsigned = [
        PREFIX.as_bytes(),
        domain_separator,
        signer_hash.as_slice(),
        data_hash.as_slice(),
    ]
    .concat();

    Ok(Keccak256::digest(unsigned).into())
}

pub fn encode_payload(payload: &Payload) -> Result<Vec<u8>, ContractError> {
    let command_type = CommandType::from(payload).into();

    match payload {
        Payload::Messages(messages) => {
            let messages = messages
                .iter()
                .map(Message::try_from)
                .map_ok(|m| Token::Tuple(m.into_tokens()))
                .collect::<Result<Vec<_>, _>>()
                .change_context(ContractError::InvalidMessage)?;

            Ok(abi_encode(&[command_type, Token::Array(messages)]))
        }
        Payload::VerifierSet(verifier_set) => Ok(abi_encode(&[
            command_type,
            Token::Tuple(
                WeightedSigners::try_from(verifier_set)
                    .change_context(ContractError::InvalidVerifierSet)?
                    .into_tokens(),
            ),
        ])),
    }
}

pub fn encode_execute_data(
    domain_separator: &Hash,
    verifier_set: &VerifierSet,
    signers: Vec<SignerWithSig>,
    payload: &Payload,
) -> error_stack::Result<HexBinary, ContractError> {
    let signers = to_recoverable(
        payload_digest(domain_separator, verifier_set, payload)?,
        signers,
    );

    let proof = Proof::new(verifier_set, signers).change_context(ContractError::Proof)?;

    let (selector, encoded) = match payload {
        Payload::Messages(messages) => {
            let messages: Vec<_> = messages
                .iter()
                .map(Message::try_from)
                .collect::<Result<_, _>>()
                .change_context(ContractError::InvalidMessage)?;

            (
                ApproveMessagesCall::selector(),
                abi_encode(&ApproveMessagesCall { messages, proof }.into_tokens()),
            )
        }
        Payload::VerifierSet(new_verifier_set) => {
            let new_signers = WeightedSigners::try_from(new_verifier_set)
                .change_context(ContractError::InvalidVerifierSet)?;

            (
                RotateSignersCall::selector(),
                abi_encode(&RotateSignersCall { new_signers, proof }.into_tokens()),
            )
        }
    };

    Ok(selector
        .into_iter()
        .chain(encoded)
        .collect::<Vec<_>>()
        .into())
}

// Convert non-recoverable ECDSA signatures to recoverable ones.
fn to_recoverable<M>(msg: M, signers: Vec<SignerWithSig>) -> Vec<SignerWithSig>
where
    M: AsRef<[u8]>,
{
    let recovery_transform = |recovery_byte: RecoveryId| -> u8 {
        recovery_byte
            .to_byte()
            .checked_add(27)
            .expect("overflow when adding 27 to recovery byte")
    };

    signers
        .into_iter()
        .map(|mut signer| {
            if let Signature::Ecdsa(nonrecoverable) = signer.signature {
                signer.signature = nonrecoverable
                    .to_recoverable(msg.as_ref(), &signer.signer.pub_key, recovery_transform)
                    .map(Signature::EcdsaRecoverable)
                    .expect("failed to convert non-recoverable signature to recoverable");
            }

            signer
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use assert_ok::assert_ok;
    use cosmwasm_std::HexBinary;
    use elliptic_curve::consts::U32;
    use ethers_core::types::Signature as EthersSignature;
    use evm_gateway::evm_address;
    use generic_array::GenericArray;
    use hex::FromHex;
    use itertools::Itertools;
    use k256::ecdsa::{RecoveryId, Signature as K256Signature};
    use multisig::{KeyType, KeyTyped, Signature, Signer, SignerWithSig};

    use crate::encoding::abi::{encode_execute_data, payload_digest, CommandType};
    use crate::test::test_data::{
        curr_verifier_set, domain_separator, messages, new_verifier_set, verifier_set_from_pub_keys,
    };
    use crate::Payload;

    #[test]
    fn command_type_from_payload() {
        let payload = Payload::Messages(vec![]);
        assert_eq!(CommandType::from(&payload), CommandType::ApproveMessages);

        let payload = Payload::VerifierSet(new_verifier_set());
        assert_eq!(CommandType::from(&payload), CommandType::RotateSigners);
    }

    #[test]
    fn abi_verifier_set_payload_digest() {
        let domain_separator = domain_separator();

        let new_pub_keys = vec![
            "02de8b0cc10de1becab121cb1254a7b4075866b6e040d5a4cdd38c7ea6c68c7d0a",
            "025a08780e7b80e64511006ec4db4128e18b31f05e9c8a4ef285322991d5f17332",
            "03935a5be97cf2148cb5cb88d5f097a235859a572f46e53da907e80fd5578f9243",
            "02515a95a89320988ff96f5e990b6d4c0a6807072f9b01c9ae634cf846bae2bd08",
            "02464111b31e5d174ec44c172f5e3913d0a35344ef6c2cd8215494f23648ec3420",
        ];

        let mut new_verifier_set = verifier_set_from_pub_keys(new_pub_keys);
        new_verifier_set.created_at = 2024;

        let payload_digest = assert_ok!(payload_digest(
            &domain_separator,
            &curr_verifier_set(),
            &Payload::VerifierSet(new_verifier_set),
        ));

        goldie::assert!(hex::encode(payload_digest));
    }

    #[test]
    fn abi_approve_messages_payload_digest() {
        let domain_separator = domain_separator();
        let payload_digest = assert_ok!(payload_digest(
            &domain_separator,
            &curr_verifier_set(),
            &Payload::Messages(messages()),
        ));

        goldie::assert!(hex::encode(payload_digest));
    }

    #[test]
    fn abi_rotate_signers_execute_data() {
        let domain_separator = domain_separator();

        let new_pub_keys = vec![
            "0352a321079b435a4566ac8c92ab18584d8537d563f6c2c0bbbf58246ad047c611",
            "03b80cd1fff796fb80a82f4d45b812451668791a85a58c8c0b5939d75f126f80b1",
            "0251f7035a693e804eaed139009ede4ef62215914ccf9080027d53ef6bbb8897c5",
            "03a907596748daa5ae9c522445529ca38d0ea2c47a908c30643ca37a0e6e12160d",
            "03c55d66787c66f37257ef4b320ddcb64623d59e9bf0f3ec0f8ac7311b70cdd2c8",
        ];

        let mut new_verifier_set = verifier_set_from_pub_keys(new_pub_keys);
        new_verifier_set.created_at = 2024;

        let verifier_set = curr_verifier_set();

        // Generated signatures are already sorted by weight and evm address
        let sigs: Vec<_> = vec![
            "e3a7c09bfa26df8bbd207df89d7ba01100b809324b2987e1426081284a50485345a5a20b6d1d5844470513099937f1015ce8f4832d3df97d053f044103434d8c1b",
            "895dacfb63684da2360394d5127696129bd0da531d6877348ff840fb328297f870773df3c259d15dd28dbd51d87b910e4156ff2f3c1dc5f64d337dea7968a9401b",
            "7c685ecc8a42da4cd9d6de7860b0fddebb4e2e934357500257c1070b1a15be5e27f13b627cf9fa44f59d535af96be0a5ec214d988c48e2b5aaf3ba537d0215bb1b",
        ].into_iter().map(|sig| HexBinary::from_hex(sig).unwrap()).collect();

        let signers_with_sigs = signers_with_sigs(verifier_set.signers.values(), sigs);

        let payload = Payload::VerifierSet(new_verifier_set);

        let execute_data = assert_ok!(encode_execute_data(
            &domain_separator,
            &verifier_set,
            signers_with_sigs,
            &payload
        ));

        goldie::assert!(execute_data.to_hex());
    }

    #[test]
    fn abi_approve_messages_execute_data() {
        let domain_separator = domain_separator();
        let verifier_set = curr_verifier_set();

        // Generated signatures are already sorted by weight and evm address
        let sigs: Vec<_> = vec![
            "756473c3061df7ea3fef7c52e0e875dca2c93f08ce4f1d33e694d64c713a56842017d92f0a1b796afe1c5343677ff261a072fb210ff3d43cc2784c0774d4da7b1b",
            "5bdad2b95e700283402392a2f5878d185f92d588a6b4868460977c4f06f4216f0452c2e215c2878fe6e146db5b74f278716a99b418c6b2cb1d812ad28e686cd81c",
            "4c9c52a99a3941a384c4a80b3c5a14c059020d3d2f29be210717bdb9270ed55937fcec824313c90c198188ea8eb3b47c2bafe5e96c11f79ec793d589358024191b",
        ].into_iter().map(|sig| HexBinary::from_hex(sig).unwrap()).collect();

        let signers_with_sigs = signers_with_sigs(verifier_set.signers.values(), sigs);

        let payload = Payload::Messages(messages());
        let execute_data = assert_ok!(encode_execute_data(
            &domain_separator,
            &verifier_set,
            signers_with_sigs,
            &payload
        ));
        goldie::assert!(execute_data.to_hex());
    }

    #[test]
    fn should_convert_signature_to_recoverable() {
        let ecdsa_signature = EthersSignature::from_str("74ab5ec395cdafd861dec309c30f6cf8884fc9905eb861171e636d9797478adb60b2bfceb7db0a08769ed7a60006096d3e0f6d3783d125600ac6306180ecbc6f1b").unwrap();
        let pub_key =
            Vec::from_hex("03571a2dcec96eecc7950c9f36367fd459b8d334bac01ac153b7ed3dcf4025fc22")
                .unwrap();

        let digest = "6ac52b00f4256d98d53c256949288135c14242a39001d5fdfa564ea003ccaf92";

        let signature = {
            let mut r_bytes = [0u8; 32];
            let mut s_bytes = [0u8; 32];
            ecdsa_signature.r.to_big_endian(&mut r_bytes);
            ecdsa_signature.s.to_big_endian(&mut s_bytes);
            let gar: &GenericArray<u8, U32> = GenericArray::from_slice(&r_bytes);
            let gas: &GenericArray<u8, U32> = GenericArray::from_slice(&s_bytes);

            K256Signature::from_scalars(*gar, *gas).unwrap()
        };

        let non_recoverable: Signature = (KeyType::Ecdsa, HexBinary::from(signature.to_vec()))
            .try_into()
            .unwrap();

        if let Signature::Ecdsa(non_recoverable) = non_recoverable {
            let recoverable = non_recoverable
                .to_recoverable(
                    HexBinary::from_hex(digest).unwrap().as_slice(),
                    &multisig::PublicKey::Ecdsa(HexBinary::from(pub_key.to_vec())),
                    |recovery_byte: RecoveryId| -> u8 {
                        recovery_byte
                            .to_byte()
                            .checked_add(27)
                            .expect("overflow when adding 27 to recovery byte")
                    },
                )
                .unwrap();

            assert_eq!(recoverable.as_ref(), ecdsa_signature.to_vec().as_slice());
        } else {
            panic!("Invalid signature type")
        }
    }

    fn signers_with_sigs<'a>(
        signers: impl Iterator<Item = &'a Signer>,
        sigs: Vec<HexBinary>,
    ) -> Vec<SignerWithSig> {
        signers
            .sorted_by(|s1, s2| {
                Ord::cmp(
                    &evm_address(&s1.pub_key).unwrap(),
                    &evm_address(&s2.pub_key).unwrap(),
                )
            })
            .zip(sigs)
            .map(|(signer, sig)| {
                signer.with_sig(Signature::try_from((signer.pub_key.key_type(), sig)).unwrap())
            })
            .collect()
    }
}
