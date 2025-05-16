use axelar_wasm_std::hash::Hash;
use axelar_wasm_std::FnExt;
use cosmwasm_std::HexBinary;
use error_stack::{Result, ResultExt};
use multisig::{SignerWithSig,VerifierSet};
use sha3::{Digest, Keccak256};
use stellar::{Message, Messages, Proof, WeightedSigners};
use stellar_xdr::curr::{Limits, ScVal, WriteXdr};

use crate::error::ContractError;
use crate::Payload;

pub fn payload_digest(
    domain_separator: &Hash,
    verifier_set: &VerifierSet,
    payload: &Payload,
) -> Result<Hash, ContractError> {
    let data_hash = match payload {
        Payload::Messages(messages) => messages
            .iter()
            .map(Message::try_from)
            .collect::<Result<Vec<_>, _>>()
            .change_context(ContractError::InvalidMessage)?
            .then(Messages::from)
            .messages_approval_hash(),
        Payload::VerifierSet(verifier_set) => WeightedSigners::try_from(verifier_set)
            .change_context(ContractError::InvalidVerifierSet)?
            .signers_rotation_hash(),
    }
    .change_context(ContractError::SerializeData)?;

    let signers_hash = WeightedSigners::try_from(verifier_set)
        .change_context(ContractError::InvalidVerifierSet)?
        .hash()
        .change_context(ContractError::SerializeData)?;

    let unsigned = [
        domain_separator,
        signers_hash.as_slice(),
        data_hash.as_slice(),
    ]
    .concat();

    Ok(Keccak256::digest(unsigned).into())
}

/// `encode_execute_data` returns the XDR encoded external gateway function call args.
/// The relayer will use this data to submit the payload to the contract.
pub fn encode_execute_data(
    verifier_set: &VerifierSet,
    signatures: Vec<SignerWithSig>,
    payload: &Payload,
) -> Result<HexBinary, ContractError> {
    let payload = match payload {
        Payload::Messages(messages) => ScVal::try_from(
            messages
                .iter()
                .map(Message::try_from)
                .collect::<Result<Vec<_>, _>>()
                .change_context(ContractError::InvalidMessage)?
                .then(Messages::from),
        ),
        Payload::VerifierSet(verifier_set) => ScVal::try_from(
            WeightedSigners::try_from(verifier_set)
                .change_context(ContractError::InvalidVerifierSet)?,
        ),
    }
    .change_context(ContractError::SerializeData)?;

    let proof =
        Proof::try_from((verifier_set.clone(), signatures)).change_context(ContractError::Proof)?;

    let execute_data = ScVal::try_from((payload, proof))
        .expect("must convert tuple of size 2 to ScVec")
        .to_xdr(Limits::none())
        .change_context(ContractError::SerializeData)?;

    Ok(execute_data.as_slice().into())
}
#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::MockApi;
    use cosmwasm_std::{HexBinary, Uint128};
    use multisig::key::KeyType::Ed25519;
    use multisig::key::Signature;
    use multisig::msg::{Signer, SignerWithSig};
    use multisig::verifier_set::VerifierSet;
    use router_api::{CrossChainId, Message};

    use crate::encoding::stellar_xdr::{encode_execute_data, payload_digest};
    use crate::Payload;

    #[test]
    fn stellar_messages_payload_digest() {
        let signers_data = vec![
            (
                "addr_1",
                "508bcac3df50837e0b093aebc549211ba72bd1e7c1830a288b816b677d62a046",
                9u128,
            ),
            (
                "addr_2",
                "5c186341e6392ff06b35b2b80a05f99cdd1dd7d5b436f2eef1a6dd08c07c9463",
                4u128,
            ),
            (
                "addr_3",
                "78c860cbba0b74a728bdc2ae05feef5a14c8903f59d59525ed5bea9b52027d0e",
                3u128,
            ),
            (
                "addr_4",
                "ac1276368dab35ecc413c5008f184df4005e8773ea44ce3c980bc3dbe45f7521",
                3u128,
            ),
            (
                "addr_4",
                "856d2aedc159b543f3150fd9e013ed5cc4d5d32659595e7bedbec279c28ccbe0",
                5u128,
            ),
            (
                "addr_5",
                "e2a6a040c4a31f8131651fb669d514066963e2fde91feb86350d494a6e02f0fa",
                6u128,
            ),
        ];
        let verifier_set = gen_verifier_set(signers_data, 22, 2024);

        let payload = Payload::Messages(vec![Message {
            cc_id: CrossChainId {
                source_chain: "source".parse().unwrap(),
                message_id: "test".parse().unwrap(),
            },
            source_address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHK3M"
                .parse()
                .unwrap(),
            destination_chain: "stellar".parse().unwrap(),
            destination_address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMDR4"
                .parse()
                .unwrap(),
            payload_hash: HexBinary::from_hex(
                "65ad329dc342a82bd1daedc42e183e6e2c272b8e2e3fd7c8f81d089736d0bc3c",
            )
            .unwrap()
            .to_array()
            .unwrap(),
        }]);
        let domain_separator: [u8; 32] =
            HexBinary::from_hex("2a15376c1277252b1bcce5a6ecd781bfbc2697dfd969ff58d8e2e116018b501e")
                .unwrap()
                .to_array()
                .unwrap();
        goldie::assert!(hex::encode(
            payload_digest(&domain_separator, &verifier_set, &payload).unwrap()
        ));
    }

    #[test]
    fn stellar_verifier_set_payload_digest() {
        let verifier_set = gen_verifier_set(
            vec![(
                "addr_1",
                "bf95c447eb2e694974ee2cf5f17e7165bc884a0cb676bb4de50c604bb7a6ea77",
                4u128,
            )],
            1,
            2024,
        );
        let signers_data = vec![
            (
                "addr_1",
                "5086d25f94b8c42faf7ef4325516864e179fcb2a1a9321720f0fc2b249105106",
                5u128,
            ),
            (
                "addr_2",
                "57a446f70d8243b7d5e08edcd9c5774f3f0257940df7aa84bca5b1acfc0f3ba3",
                7u128,
            ),
            (
                "addr_3",
                "5a3211139cca5cee83096e8009aadf6405d84f5137706bc1db68f53cbb202054",
                9u128,
            ),
            (
                "addr_4",
                "9d8774a24acce628658dc93e41c56972ded010c07b731306b54282890113d60f",
                7u128,
            ),
            (
                "addr_5",
                "a99083342953620013c9c61f8000a8778915337632ac601458c6c93387d963f5",
                7u128,
            ),
        ];
        let payload = Payload::VerifierSet(gen_verifier_set(signers_data, 27, 2024));
        let domain_separator: [u8; 32] =
            HexBinary::from_hex("6773bd037510492f863cba62a0f3c55ac846883f33cae7266aff8be5eb9681e8")
                .unwrap()
                .to_array()
                .unwrap();

        goldie::assert!(hex::encode(
            payload_digest(&domain_separator, &verifier_set, &payload).unwrap()
        ));
    }

    #[test]
    fn stellar_approve_messages_execute_data() {
        let signers_data = vec![
            (
                "addr_1",
                "12f7d9a9463212335914b39ee90bfa2045f90b64c1f2d7b58ed335282abac4a4",
                8u128,
                Some("b5b3b0749aa585f866d802e32ca4a6356f82eb52e2a1b4797cbaa30f3d755462f2eb995c70d9099e436b8a48498e4d613ff2d3ca7618973a36c2fde17493180f"),
            ),
            (
                "addr_2",
                "4c3863e4b0252a8674c1c6ad70b3ca3002b400b49ddfae5583b21907e65c5dd8",
                1u128,
                None
            ),
            (
                "addr_3",
                "c35aa94d2038f258ecb1bb28fbc8a83ab79d2dc0a7223fd528a8f52a14c03292",
                7u128,
                Some("28e2c8accfa1c2db93349c6d3f783004d6a92cdbf322b92b3555315999e0eaf5d8bdf9deb58d798168a880972e81b8513dcb942de44862317d501cf7445c660a")
            ),

        ];

        let verifier_set = gen_verifier_set(
            signers_data
                .iter()
                .map(|(t1, t2, t3, _)| (*t1, *t2, *t3))
                .collect(),
            10,
            2024,
        );

        let signer_with_sig = gen_signers_with_sig(signers_data);

        let payload = Payload::Messages(vec![Message {
            cc_id: CrossChainId {
                source_chain: "source".parse().unwrap(),
                message_id: "test".parse().unwrap(),
            },
            source_address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHK3M"
                .parse()
                .unwrap(),
            destination_chain: "stellar".parse().unwrap(),
            destination_address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMDR4"
                .parse()
                .unwrap(),
            payload_hash: HexBinary::from_hex(
                "595c9108df17d1cc43e8268ec1516064299c1388bcc86fdd566bcdf400a0a1ed",
            )
            .unwrap()
            .to_array()
            .unwrap(),
        }]);

        goldie::assert!(
            encode_execute_data(&verifier_set, signer_with_sig, &payload)
                .unwrap()
                .to_hex()
        );
    }

    #[test]
    fn stellar_rotate_signers_execute_data() {
        let signers_data = vec![
            (
                "addr_1",
                "77dd4768dda195f8080fe970be8fec5fee9cea781718158ce19d4a331442fd57",
                2u128,
                Some("91db8ad94ab379ee9021caeb3ee852582d09d06801213256cbd2937f2ad8182f518fde7a7f8c801adde7161e05cbbb9841ac0bf3290831570a54c6ae3d089703"),
            ),
            (
                "addr_2",
                "c35aa94d2038f258ecb1bb28fbc8a83ab79d2dc0a7223fd528a8f52a14c03292",
                1u128,
                None,
            ),
        ];

        let verifier_set = gen_verifier_set(
            signers_data
                .iter()
                .map(|(t1, t2, t3, _)| (*t1, *t2, *t3))
                .collect(),
            1,
            2024,
        );

        let signer_with_sig = gen_signers_with_sig(signers_data);

        let payload = Payload::VerifierSet(gen_verifier_set(
            vec![
                (
                    "addr_1",
                    "358a2305fc783b6072049ee6f5f76fb14c3a14d7c01e36d9ef502661bf46a011",
                    9u128,
                ),
                (
                    "addr_2",
                    "3b1caf530189a9a65ae347b18cb8bf88729ba90d2aeaf7f185b600400ab49891",
                    1u128,
                ),
                (
                    "addr_3",
                    "531616448afd45c0e3e053622cbccb65d8fc99cd2f02636d728739811e72eafb",
                    3u128,
                ),
                (
                    "addr_4",
                    "5e4c8ec6569774adf69cb6e2bc4ef556c2fc6b412c85d6a5e0b18d54b069e594",
                    7u128,
                ),
                (
                    "addr_5",
                    "8097528d987899f887c08c23a928dfe6fe9550010d19c7be0b46b5d0596997cc",
                    3u128,
                ),
            ],
            17,
            2024,
        ));

        goldie::assert!(
            encode_execute_data(&verifier_set, signer_with_sig, &payload)
                .unwrap()
                .to_hex()
        );
    }

    fn gen_verifier_set(
        signers_data: Vec<(&str, &str, u128)>,
        threshold: u128,
        created_at: u64,
    ) -> VerifierSet {
        VerifierSet {
            signers: signers_data
                .into_iter()
                .map(|(addr, pub_key, weight)| {
                    (
                        addr.to_string(),
                        Signer {
                            address: MockApi::default().addr_make(addr),
                            pub_key: (Ed25519, HexBinary::from_hex(pub_key).unwrap())
                                .try_into()
                                .unwrap(),
                            weight: Uint128::from(weight),
                        },
                    )
                })
                .collect(),
            threshold: threshold.into(),
            created_at,
        }
    }

    fn gen_signers_with_sig(
        signers_data: Vec<(&str, &str, u128, Option<&str>)>,
    ) -> Vec<SignerWithSig> {
        signers_data
            .into_iter()
            .filter_map(|(addr, pub_key, weight, sig)| {
                sig.map(|signature| (addr, pub_key, weight, signature))
            })
            .map(|(addr, pub_key, weight, sig)| {
                Signer {
                    address: MockApi::default().addr_make(addr),
                    pub_key: (Ed25519, HexBinary::from_hex(pub_key).unwrap())
                        .try_into()
                        .unwrap(),
                    weight: Uint128::from(weight),
                }
                .with_sig(
                    Signature::try_from((Ed25519, HexBinary::from_hex(sig).unwrap())).unwrap(),
                )
            })
            .collect::<Vec<_>>()
    }
}
