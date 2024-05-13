use alloy_primitives::Bytes;
use alloy_sol_types::{sol, SolCall};
use cosmwasm_std::HexBinary;

use axelar_wasm_std::hash::Hash;
use multisig::{key::Signature, msg::SignerWithSig, worker_set::WorkerSet};

use crate::{
    encoding::abi::{evm_address, Message, Proof, WeightedSigners},
    error::ContractError,
    payload::Payload,
};

sol!(
    IAxelarAmplifierGateway,
    "src/encoding/abi/solidity/IAxelarAmplifierGateway.json"
);

impl From<WeightedSigners> for IAxelarAmplifierGateway::WeightedSigners {
    fn from(signers: WeightedSigners) -> Self {
        IAxelarAmplifierGateway::WeightedSigners {
            signers: signers
                .signers
                .iter()
                .map(|signer| IAxelarAmplifierGateway::WeightedSigner {
                    signer: signer.signer,
                    weight: signer.weight,
                })
                .collect(),
            threshold: signers.threshold,
            nonce: signers.nonce,
        }
    }
}

impl From<Proof> for IAxelarAmplifierGateway::Proof {
    fn from(proof: Proof) -> Self {
        IAxelarAmplifierGateway::Proof {
            signers: proof.signers.into(),
            signatures: proof.signatures,
        }
    }
}

impl From<Message> for IAxelarAmplifierGateway::Message {
    fn from(message: Message) -> Self {
        IAxelarAmplifierGateway::Message {
            messageId: message.messageId,
            sourceChain: message.sourceChain,
            sourceAddress: message.sourceAddress,
            contractAddress: message.contractAddress,
            payloadHash: message.payloadHash,
        }
    }
}

impl Proof {
    /// Proof contains the entire worker set and optimized signatures. Signatures are sorted in ascending order based on the signer's address.
    pub fn new(worker_set: &WorkerSet, mut signers_with_sigs: Vec<SignerWithSig>) -> Self {
        signers_with_sigs.sort_by_key(|signer| {
            evm_address(&signer.signer.pub_key).expect("failed to convert pub key to evm address")
        });

        let signatures = signers_with_sigs
            .into_iter()
            .map(|signer| Bytes::copy_from_slice(signer.signature.as_ref()))
            .collect();

        Proof {
            signers: WeightedSigners::from(worker_set),
            signatures,
        }
    }
}

pub fn encode(
    worker_set: &WorkerSet,
    signers: Vec<SignerWithSig>,
    payload_digest: &Hash,
    payload: &Payload,
) -> Result<HexBinary, ContractError> {
    let signers = to_recoverable(payload_digest.as_slice(), signers);

    let proof = Proof::new(worker_set, signers);

    let data = match payload {
        Payload::Messages(messages) => {
            let messages: Vec<_> = messages
                .iter()
                .map(|msg| Message::try_from(msg).map(IAxelarAmplifierGateway::Message::from))
                .collect::<Result<Vec<_>, _>>()?;

            IAxelarAmplifierGateway::approveMessagesCall::new((messages, proof.into()))
                .abi_encode()
                .into()
        }
        Payload::WorkerSet(new_worker_set) => {
            let new_worker_set = WeightedSigners::from(new_worker_set);

            IAxelarAmplifierGateway::rotateSignersCall::new((new_worker_set.into(), proof.into()))
                .abi_encode()
                .into()
        }
    };

    Ok(data)
}

// Convert non-recoverable ECDSA signatures to recoverable ones.
fn to_recoverable(msg: &[u8], signers: Vec<SignerWithSig>) -> Vec<SignerWithSig> {
    signers
        .into_iter()
        .map(|mut signer| {
            if let Signature::Ecdsa(nonrecoverable) = signer.signature {
                signer.signature = nonrecoverable
                    .to_recoverable(msg, &signer.signer.pub_key, add27)
                    .map(Signature::EcdsaRecoverable)
                    .expect("failed to convert non-recoverable signature to recoverable");
            }

            signer
        })
        .collect()
}

pub fn add27(recovery_byte: k256::ecdsa::RecoveryId) -> u8 {
    recovery_byte
        .to_byte()
        .checked_add(27)
        .expect("overflow when adding 27 to recovery byte")
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy_primitives::Signature as EcdsaSignature;
    use cosmwasm_std::HexBinary;
    use elliptic_curve::consts::U32;
    use generic_array::GenericArray;
    use hex::FromHex;
    use itertools::Itertools;
    use k256::ecdsa::Signature as K256Signature;
    use sha3::{Digest, Keccak256};

    use axelar_wasm_std::hash::Hash;
    use multisig::key::{KeyType, KeyTyped, Signature};
    use multisig::msg::{Signer, SignerWithSig};

    use crate::{
        encoding::abi::{
            evm_address,
            execute_data::{add27, encode},
            payload_hash_to_sign,
        },
        payload::Payload,
        test::test_data::{curr_worker_set, domain_separator, messages, worker_set_from_pub_keys},
    };

    #[test]
    fn rotate_signers_function_data() {
        // RotateSigners function calldata hash generated by axelar-gmp-sdk-solidity unit tests
        let expected_data_hash =
            HexBinary::from_hex("52c65e01d464f6e440ebff7561b09edc1c9ff7754dd8bdaaa0410a952b9824cb")
                .unwrap();

        let domain_separator = domain_separator();

        let new_pub_keys = vec![
            "0352a321079b435a4566ac8c92ab18584d8537d563f6c2c0bbbf58246ad047c611",
            "03b80cd1fff796fb80a82f4d45b812451668791a85a58c8c0b5939d75f126f80b1",
            "0251f7035a693e804eaed139009ede4ef62215914ccf9080027d53ef6bbb8897c5",
            "03a907596748daa5ae9c522445529ca38d0ea2c47a908c30643ca37a0e6e12160d",
            "03c55d66787c66f37257ef4b320ddcb64623d59e9bf0f3ec0f8ac7311b70cdd2c8",
        ];

        let new_worker_set = worker_set_from_pub_keys(new_pub_keys);
        let worker_set = curr_worker_set();

        // Generated signatures are already sorted by weight and evm address
        let sigs: Vec<_> = vec![
            "e3a7c09bfa26df8bbd207df89d7ba01100b809324b2987e1426081284a50485345a5a20b6d1d5844470513099937f1015ce8f4832d3df97d053f044103434d8c1b",
            "895dacfb63684da2360394d5127696129bd0da531d6877348ff840fb328297f870773df3c259d15dd28dbd51d87b910e4156ff2f3c1dc5f64d337dea7968a9401b",
            "7c685ecc8a42da4cd9d6de7860b0fddebb4e2e934357500257c1070b1a15be5e27f13b627cf9fa44f59d535af96be0a5ec214d988c48e2b5aaf3ba537d0215bb1b",
        ].into_iter().map(|sig| HexBinary::from_hex(sig).unwrap()).collect();

        let signers_with_sigs = signers_with_sigs(worker_set.signers.values(), sigs);

        let payload = Payload::WorkerSet(new_worker_set);
        let payload_hash: Hash = payload_hash_to_sign(&domain_separator, &worker_set, &payload)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();

        let execute_data = encode(&worker_set, signers_with_sigs, &payload_hash, &payload).unwrap();
        let data_hash = Keccak256::digest(execute_data.as_slice());

        assert_eq!(HexBinary::from(data_hash.as_slice()), expected_data_hash);
    }

    #[test]
    fn should_convert_signature_to_recoverable() {
        let ecdsa_signature = EcdsaSignature::from_str("74ab5ec395cdafd861dec309c30f6cf8884fc9905eb861171e636d9797478adb60b2bfceb7db0a08769ed7a60006096d3e0f6d3783d125600ac6306180ecbc6f1b").unwrap();
        let pub_key =
            Vec::from_hex("03571a2dcec96eecc7950c9f36367fd459b8d334bac01ac153b7ed3dcf4025fc22")
                .unwrap();

        let digest = "6ac52b00f4256d98d53c256949288135c14242a39001d5fdfa564ea003ccaf92";

        let signature = {
            let r_bytes: [u8; 32] = ecdsa_signature.r().to_be_bytes();
            let s_bytes: [u8; 32] = ecdsa_signature.s().to_be_bytes();
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
                    &multisig::key::PublicKey::Ecdsa(HexBinary::from(pub_key.to_vec())),
                    add27,
                )
                .unwrap();

            assert_eq!(recoverable.as_ref(), ecdsa_signature.as_bytes().as_slice());
        } else {
            panic!("Invalid signature type")
        }
    }

    #[test]
    fn approve_messages_function_data() {
        // ApproveMessages function calldata hash generated by axelar-gmp-sdk-solidity unit tests
        let expected_data_hash =
            HexBinary::from_hex("cf6200f6889b7157af0bfcb2eaaabc03d89b94428dcbe613f5844f4f593c050d")
                .unwrap();

        let domain_separator = domain_separator();
        let worker_set = curr_worker_set();

        // Generated signatures are already sorted by weight and evm address
        let sigs: Vec<_> = vec![
            "6e320a96a33260b488c6c4a2fa007345a4db974bf9d94a9568edf79452ee0e805eedb7c4e67ce16fb5cc0691b04b5caf3b0014e1133d5175a9bc47d917f57e251c",
            "fdd7269bbc41946f73ca744a4037fd1e9fcf2d2a93db8cfe2143c2b0ea52bd96300c7f61803cebaff1590bc137ca0503697a502d06a1c4998aaceb77c0a91c6b1c",
            "01363790ed71e5070be5d79277350b3300cbba90b1141dbcf49103eaf113178c30947ff9fb293d23860aa33150b883e0852faae0fad1218550a8c730ac9961fc1b",
        ].into_iter().map(|sig| HexBinary::from_hex(sig).unwrap()).collect();

        let signers_with_sigs = signers_with_sigs(worker_set.signers.values(), sigs);

        let payload = Payload::Messages(messages());
        let payload_hash: Hash = payload_hash_to_sign(&domain_separator, &worker_set, &payload)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();

        let execute_data = encode(&worker_set, signers_with_sigs, &payload_hash, &payload).unwrap();
        let data_hash = Keccak256::digest(execute_data.as_slice());

        assert_eq!(HexBinary::from(data_hash.as_slice()), expected_data_hash);
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
