use axelar_wasm_std::hash::Hash;
use axelar_wasm_std::FnExt;
use error_stack::{Result, ResultExt};
use multisig::verifier_set::VerifierSet;
use sha3::{Digest, Keccak256};
use stellar::{Message, Messages, WeightedSigners};

use crate::error::ContractError;
use crate::payload::Payload;

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

#[cfg(test)]
mod tests {
    use cosmwasm_std::{Addr, HexBinary, Uint128};
    use multisig::key::KeyType;
    use multisig::msg::Signer;
    use multisig::verifier_set::VerifierSet;
    use router_api::{CrossChainId, Message};

    use crate::encoding::stellar_xdr::payload_digest;
    use crate::payload::Payload;

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
        let verifier_set = gen_veifier_set(signers_data, 22, 2024);

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
        let verifier_set = gen_veifier_set(
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
        let payload = Payload::VerifierSet(gen_veifier_set(signers_data, 27, 2024));
        let domain_separator: [u8; 32] =
            HexBinary::from_hex("6773bd037510492f863cba62a0f3c55ac846883f33cae7266aff8be5eb9681e8")
                .unwrap()
                .to_array()
                .unwrap();

        goldie::assert!(hex::encode(
            payload_digest(&domain_separator, &verifier_set, &payload).unwrap()
        ));
    }

    fn gen_veifier_set(
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
                            address: Addr::unchecked(addr),
                            pub_key: (KeyType::Ed25519, HexBinary::from_hex(pub_key).unwrap())
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
}
