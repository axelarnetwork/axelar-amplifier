use aleo_gmp_types::aleo_struct::generated_structs::{
    ExecuteData, ExecuteDataVerifierSet, Message, MessageGroup, Messages, PayloadDigest,
};
use aleo_gmp_types::aleo_struct::AxelarToLeo;
use aleo_gmp_types::utils::ToBytesExt;
use aleo_network_config::network::NetworkConfig;
use axelar_wasm_std::hash::Hash;
use cosmwasm_std::HexBinary;
use error_stack::{report, Result, ResultExt};
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;
use snarkvm_cosmwasm::console::program::Network;
use snarkvm_cosmwasm::prelude::{
    CanaryV0, Group, MainnetV0, Plaintext, TestnetV0, ToBits as _, ToBytes as _, Zero as _,
};

use crate::error::ContractError;
use crate::payload::Payload;

pub fn payload_digest(
    network: &NetworkConfig,
    domain_separator: &Hash,
    verifier_set: &VerifierSet,
    payload: &Payload,
) -> Result<Hash, ContractError> {
    match network {
        NetworkConfig::TestnetV0 => {
            payload_digest_inner::<TestnetV0>(domain_separator, verifier_set, payload)
        }
        NetworkConfig::MainnetV0 => {
            payload_digest_inner::<MainnetV0>(domain_separator, verifier_set, payload)
        }
        NetworkConfig::CanaryV0 => {
            payload_digest_inner::<CanaryV0>(domain_separator, verifier_set, payload)
        }
    }
}

fn payload_digest_inner<N: Network>(
    domain_separator: &Hash,
    verifier_set: &VerifierSet,
    payload: &Payload,
) -> Result<Hash, ContractError> {
    use aleo_gmp_types::aleo_struct::AxelarToLeo;

    let data_hash = match payload {
        Payload::Messages(messages) => {
            let aleo_messages: Vec<Group<N>> = messages
                .iter()
                .filter_map(|m| {
                    let leo_verifier_set = m.to_leo().ok()?;

                    aleo_gmp_types::utils::bhp(&leo_verifier_set).ok()
                })
                .collect();

            let mut groups = aleo_messages
                .into_iter()
                .chain(std::iter::repeat(Group::<N>::zero()))
                .take(48);

            // Its safe to unwrap because we are taking 48 elements
            let array1: [Group<N>; 24] = std::array::from_fn(|_| groups.next().unwrap());
            let array2: [Group<N>; 24] = std::array::from_fn(|_| groups.next().unwrap());

            let messages: MessageGroup<N> = MessageGroup {
                messages: [array1, array2],
            };

            Plaintext::try_from(&messages)
                .and_then(|plaintext| N::hash_to_group_bhp256(&plaintext.to_bits_le()))
                .map_err(|_| {
                    report!(ContractError::AleoError(
                        "Failed to convert messages to plaintext".to_string()
                    ))
                })?
        }
        Payload::VerifierSet(verifier_set) => verifier_set
            .to_leo()
            .and_then(|leo_verifier_set| aleo_gmp_types::utils::bhp(&leo_verifier_set))
            .change_context_lazy(|| {
                ContractError::AleoError("Failed to convert verifier set to Leo".to_string())
            })?,
    };

    let part1 = u128::from_le_bytes(domain_separator[0..16].try_into().map_err(|_| {
        report!(ContractError::AleoError(
            "Failed to convert domain separator to u128".to_string()
        ))
    })?);
    let part2 = u128::from_le_bytes(domain_separator[16..32].try_into().map_err(|_| {
        report!(ContractError::AleoError(
            "Failed to convert domain separator to u128".to_string()
        ))
    })?);
    let domain_separator: [u128; 2] = [part1, part2];

    let payload_digest = PayloadDigest {
        domain_separator,
        signer: verifier_set.to_leo().change_context_lazy(|| {
            ContractError::AleoError("Failed to convert verifier set to Leo".to_string())
        })?,
        data_hash,
    };

    let group = Plaintext::try_from(&payload_digest)
        .and_then(|plaintext| N::hash_to_group_bhp256(&plaintext.to_bits_le()))
        .map_err(|_| {
            report!(ContractError::AleoError(
                "Failed to convert group to bytes".to_string()
            ))
        })?;

    let hash: Hash = group.to_bytes_le_array().change_context_lazy(|| {
        ContractError::AleoError("Failed to convert group to bytes".to_string())
    })?;

    Ok(hash)
}

pub fn encode_execute_data(
    network: &NetworkConfig,
    verifier_set: &VerifierSet,
    signatures: Vec<SignerWithSig>,
    payload: &Payload,
) -> Result<HexBinary, ContractError> {
    let res = match network {
        NetworkConfig::TestnetV0 => {
            encode_execute_data_inner::<TestnetV0>(verifier_set, signatures, payload)
        }
        NetworkConfig::MainnetV0 => {
            encode_execute_data_inner::<MainnetV0>(verifier_set, signatures, payload)
        }
        NetworkConfig::CanaryV0 => {
            encode_execute_data_inner::<CanaryV0>(verifier_set, signatures, payload)
        }
    };

    res.map_err(|e| {
        report!(ContractError::AleoError(format!(
            "Failed to encode execute data: {e}"
        )))
    })
}

/// The relayer will use this data to submit the payload to the contract.
fn encode_execute_data_inner<N: Network>(
    verifier_set: &VerifierSet,
    signatures: Vec<SignerWithSig>,
    payload: &Payload,
) -> Result<HexBinary, aleo_gmp_types::error::Error> {
    match payload {
        Payload::Messages(messages) => {
            let aleo_messages: Vec<Message<N>> =
                messages.iter().map(|m| m.to_leo().unwrap()).collect();

            let mut messages = aleo_messages
                .into_iter()
                .chain(std::iter::repeat(Message::<N>::default()))
                .take(48);

            // Its safe to unwrap because we are taking 48 elements
            let array1: [Message<N>; 24] = std::array::from_fn(|_| messages.next().unwrap());
            let array2: [Message<N>; 24] = std::array::from_fn(|_| messages.next().unwrap());

            let message: Messages<N> = Messages {
                messages: [array1, array2],
            };

            let weighted_signers = AxelarToLeo::<N>::to_leo(verifier_set)?;
            let proof =
                aleo_gmp_types::aleo_struct::AxelarProof::<N>::new(weighted_signers, signatures);

            let execute_data = ExecuteData {
                proof: proof.into(),
                message,
            };
            let plaintext_bytes = Plaintext::try_from(&execute_data)
                .and_then(|plaintext| plaintext.to_bytes_le())
                .map_err(|_| aleo_gmp_types::error::Error::ConversionFailed)?;

            Ok(HexBinary::from(plaintext_bytes))
        }
        Payload::VerifierSet(new_verifier_set) => {
            let new_weighted_signers = AxelarToLeo::<N>::to_leo(new_verifier_set)?;
            let proof = aleo_gmp_types::aleo_struct::AxelarProof::<N>::new(
                new_weighted_signers,
                signatures,
            );

            let weighted_signers = AxelarToLeo::<N>::to_leo(verifier_set)?;
            let execute_data = ExecuteDataVerifierSet {
                proof: proof.into(),
                payload: weighted_signers,
            };
            let plaintext_bytes = Plaintext::try_from(&execute_data)
                .and_then(|plaintext| plaintext.to_bytes_le())
                .map_err(|_| aleo_gmp_types::error::Error::ConversionFailed)?;

            Ok(HexBinary::from(plaintext_bytes))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use axelar_wasm_std::Participant;
    use cosmwasm_std::Addr;
    use multisig::key::PublicKey;
    use multisig::msg::Signer;
    use router_api::ChainNameRaw;
    use snarkos_account::Account;
    use snarkvm::prelude::{Address, FromBytes as _, ToBytes, ToFields};

    use super::*;

    fn message() -> router_api::Message {
        router_api::Message {
            cc_id: router_api::CrossChainId {
                source_chain: ChainNameRaw::from_str("aleo-2").unwrap(),
                message_id: "au1h9zxxrshyratfx0g0p5w8myqxk3ydfyxc948jysk0nxcna59ssqq0n3n3y"
                    .parse()
                    .unwrap(),
            },
            source_address: "aleo10fmsqwh059uqm74x6t6zgj93wfxtep0avevcxz0n4w9uawymkv9s7whsau"
                .parse()
                .unwrap(),
            destination_chain: "aleo-2".parse().unwrap(),
            destination_address: "foo.aleo".parse().unwrap(),
            payload_hash: [
                0xa4, 0x32, 0xdc, 0x98, 0x3d, 0xfe, 0x6f, 0xc4, 0x8b, 0xb4, 0x7a, 0x90, 0x91, 0x54,
                0x65, 0xd9, 0xc8, 0x18, 0x5b, 0x1c, 0x2a, 0xea, 0x5c, 0x87, 0xf8, 0x58, 0x18, 0xcb,
                0xa3, 0x50, 0x51, 0xc6,
            ],
        }
    }

    type CurrentNetwork = snarkvm::prelude::TestnetV0;

    // The bellow comments represent the public and private keys of the signer.
    // They are useful for manually verifying the function.
    // APrivateKey1zkpFMDCJZbRdcBcjnqjRqCrhcWFf4L9FRRSgbLpS6D47Cmo
    // aleo1v7mmux8wkue8zmuxdfks03rh85qchfmms9fkpflgs4dt87n4jy9s8nzfss
    fn aleo_sig(digest: [u8; 32]) -> SignerWithSig {
        let group_hash = Group::<CurrentNetwork>::from_bytes_le(&digest).unwrap();

        let aleo_account =
            Account::new(&mut rand::thread_rng()).expect("Failed to create Aleo account");
        let encoded_signature = aleo_account
            .sign(&group_hash.to_fields().unwrap(), &mut rand::thread_rng())
            .and_then(|signature| signature.to_bytes_le())
            .unwrap()
            .into();

        let verify_key: Address<CurrentNetwork> = aleo_account.address();
        let verify_key_encoded = verify_key.to_bytes_le().unwrap().into();

        let signer = Signer {
            address: Addr::unchecked("aleo-validator".to_string()),
            weight: 1u128.into(),
            pub_key: PublicKey::AleoSchnorr(verify_key_encoded),
        };

        let signature = multisig::key::Signature::AleoSchnorr(encoded_signature);

        SignerWithSig { signer, signature }
    }

    #[test]
    fn aleo_execute_data() {
        let domain_separator = [
            105u8, 115u8, 199u8, 41u8, 53u8, 96u8, 68u8, 100u8, 178u8, 136u8, 39u8, 20u8, 27u8,
            10u8, 70u8, 58u8, 248u8, 227u8, 72u8, 118u8, 22u8, 222u8, 105u8, 197u8, 170u8, 12u8,
            120u8, 83u8, 146u8, 201u8, 251u8, 159u8,
        ];

        let aleo_address: Address<CurrentNetwork> =
            Address::from_str("aleo1v7mmux8wkue8zmuxdfks03rh85qchfmms9fkpflgs4dt87n4jy9s8nzfss")
                .unwrap();

        let verifier_set = VerifierSet::new(
            vec![(
                Participant {
                    address: Addr::unchecked("axelar1ckguw8l9peg6sykx30cy35t6l0wpfu23xycme7"),
                    weight: 1.try_into().unwrap(),
                },
                PublicKey::AleoSchnorr(HexBinary::from(aleo_address.to_bytes_le().unwrap())),
            )],
            1u128.into(),
            4860541,
        );

        let network = NetworkConfig::TestnetV0;
        let digest = payload_digest(
            &network,
            &domain_separator,
            &verifier_set,
            &Payload::Messages(vec![message()]),
        )
        .unwrap();

        let _execute_data = encode_execute_data(
            &network,
            &verifier_set,
            vec![aleo_sig(digest)],
            &Payload::Messages(vec![message()]),
        )
        .unwrap();
    }
}
