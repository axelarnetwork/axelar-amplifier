use std::collections::BTreeMap;

use axelar_solana_encoding::hasher::NativeHasher;
use axelar_solana_gateway::processor::GatewayEvent;
use axelar_solana_gateway::processor::VerifierSetRotated;
use axelar_wasm_std::voting::Vote;
use multisig::key::PublicKey;
use multisig::verifier_set::VerifierSet;
use sha3::Digest;
use sha3::Keccak256;
use solana_sdk::pubkey::Pubkey;
use solana_transaction_status::UiTransactionStatusMeta;

use crate::handlers::solana_verify_verifier_set::VerifierSetConfirmation;
use crate::solana::verify;
use solana_transaction_status::{
    option_serializer::OptionSerializer, EncodedConfirmedTransactionWithStatusMeta,
};
use thiserror::Error;
use tracing::error;

pub fn verify_verifier_set(
    gateway_address: &Pubkey,
    tx: &UiTransactionStatusMeta,
    message: &VerifierSetConfirmation,
    domain_separator: &[u8; 32],
) -> Vote {
    use axelar_solana_encoding::types::verifier_set::verifier_set_hash;

    verify(
        gateway_address,
        tx,
        message.message_id.event_index,
        |gateway_event| {
            let GatewayEvent::VerifierSetRotated(VerifierSetRotated {
                verifier_set_hash: incoming_verifier_set_hash,
                epoch: _,
            }) = gateway_event
            else {
                return false;
            };

            let Some(verifier_set) = to_verifier_set(&message.verifier_set) else {
                error!("verifier set data structure could not be parsed");
                return false;
            };

            let Ok(desired_hash) =
                verifier_set_hash::<NativeHasher>(&verifier_set, &domain_separator)
            else {
                error!("verifier set could not be hashed");
                return false;
            };

            return &desired_hash == incoming_verifier_set_hash;
        },
    )
}

/// Transform from Axelar VerifierSet to axelar_solana_encoding VerifierSet
fn to_verifier_set(
    vs: &VerifierSet,
) -> Option<axelar_solana_encoding::types::verifier_set::VerifierSet> {
    let mut signers = BTreeMap::new();

    for (_cosmwasm_adr, signer) in vs.signers.iter() {
        let pub_key = to_pub_key(&signer.pub_key)?;
        let weight = signer.weight.u128();
        signers.insert(pub_key, weight);
    }

    let verifier_set = axelar_solana_encoding::types::verifier_set::VerifierSet {
        nonce: vs.created_at,
        signers,
        quorum: vs.threshold.u128(),
    };
    Some(verifier_set)
}

fn to_pub_key(pk: &PublicKey) -> Option<axelar_solana_encoding::types::pubkey::PublicKey> {
    use axelar_solana_encoding::types::pubkey::ED25519_PUBKEY_LEN;
    use axelar_solana_encoding::types::pubkey::SECP256K1_COMPRESSED_PUBKEY_LEN;
    Some(match pk {
        PublicKey::Ecdsa(hb) => axelar_solana_encoding::types::pubkey::PublicKey::Secp256k1(
            hb.to_array::<SECP256K1_COMPRESSED_PUBKEY_LEN>().ok()?,
        ),
        PublicKey::Ed25519(hb) => axelar_solana_encoding::types::pubkey::PublicKey::Ed25519(
            hb.to_array::<ED25519_PUBKEY_LEN>().ok()?,
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use axelar_solana_gateway::processor::VerifierSetRotated;
    use axelar_wasm_std::msg_id::Base58SolanaTxSignatureAndEventIndex;
    use axelar_wasm_std::voting::Vote;
    use cosmwasm_std::{HexBinary, Uint128};
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ecdsa_test_data};
    use solana_sdk::pubkey::Pubkey;
    use solana_transaction_status::option_serializer::OptionSerializer;
    use solana_transaction_status::UiTransactionStatusMeta;

    use super::verify_verifier_set;

    // #[test]
    // fn should_not_verify_verifier_set_if_tx_id_does_not_match() {
    //     let (gateway_address, tx_receipt, mut verifier_set) =
    //         matching_verifier_set_and_tx_receipt();

    //     verifier_set.message_id.tx_hash = Hash::random().into();
    //     assert_eq!(
    //         verify_verifier_set(&gateway_address, &tx_receipt, &verifier_set),
    //         Vote::NotFound
    //     );
    // }

    // #[test]
    // fn should_not_verify_verifier_set_if_tx_failed() {
    //     let (gateway_address, mut tx_receipt, verifier_set) =
    //         matching_verifier_set_and_tx_receipt();

    //     tx_receipt.status = Some(0u64.into());
    //     assert_eq!(
    //         verify_verifier_set(&gateway_address, &tx_receipt, &verifier_set),
    //         Vote::FailedOnChain
    //     );
    // }

    // #[test]
    // fn should_not_verify_verifier_set_if_gateway_address_does_not_match() {
    //     let (_, tx_receipt, verifier_set) = matching_verifier_set_and_tx_receipt();

    //     let gateway_address = EVMAddress::random();
    //     assert_eq!(
    //         verify_verifier_set(&gateway_address, &tx_receipt, &verifier_set),
    //         Vote::NotFound
    //     );
    // }

    // #[test]
    // fn should_not_verify_verifier_set_if_log_index_does_not_match() {
    //     let (gateway_address, tx_receipt, mut verifier_set) =
    //         matching_verifier_set_and_tx_receipt();

    //     verifier_set.message_id.event_index = 0;
    //     assert_eq!(
    //         verify_verifier_set(&gateway_address, &tx_receipt, &verifier_set),
    //         Vote::NotFound
    //     );
    //     verifier_set.message_id.event_index = 2;
    //     assert_eq!(
    //         verify_verifier_set(&gateway_address, &tx_receipt, &verifier_set),
    //         Vote::NotFound
    //     );
    //     verifier_set.message_id.event_index = 3;
    //     assert_eq!(
    //         verify_verifier_set(&gateway_address, &tx_receipt, &verifier_set),
    //         Vote::NotFound
    //     );
    // }

    // #[test]
    // fn should_not_verify_verifier_set_if_log_index_greater_than_u32_max() {
    //     let (gateway_address, tx_receipt, mut verifier_set) =
    //         matching_verifier_set_and_tx_receipt();

    //     verifier_set.message_id.event_index = u32::MAX as u64 + 1;
    //     assert_eq!(
    //         verify_verifier_set(&gateway_address, &tx_receipt, &verifier_set),
    //         Vote::NotFound
    //     );
    // }

    // #[test]
    // fn should_not_verify_verifier_set_if_verifier_set_does_not_match() {
    //     let (gateway_address, tx_receipt, mut verifier_set) =
    //         matching_verifier_set_and_tx_receipt();

    //     verifier_set.verifier_set.threshold = Uint128::from(50u64);
    //     assert_eq!(
    //         verify_verifier_set(&gateway_address, &tx_receipt, &verifier_set),
    //         Vote::NotFound
    //     );
    // }

    // #[test]
    // fn should_verify_verifier_set_if_correct() {
    //     let (gateway_address, tx_receipt, verifier_set) = matching_verifier_set_and_tx_receipt();

    //     assert_eq!(
    //         verify_verifier_set(&gateway_address, &tx_receipt, &verifier_set),
    //         Vote::SucceededOnChain
    //     );
    // }

    // #[test]
    // fn should_not_verify_msg_if_tx_id_does_not_match() {
    //     let (gateway_address, tx_receipt, mut msg) = matching_msg_and_tx_receipt();

    //     msg.message_id.tx_hash = Hash::random().into();
    //     assert_eq!(
    //         verify_message(&gateway_address, &tx_receipt, &msg),
    //         Vote::NotFound
    //     );
    // }

    // #[test]
    // fn should_not_verify_msg_if_tx_failed() {
    //     let (gateway_address, mut tx_receipt, msg) = matching_msg_and_tx_receipt();

    //     tx_receipt.status = Some(0u64.into());
    //     assert_eq!(
    //         verify_message(&gateway_address, &tx_receipt, &msg),
    //         Vote::FailedOnChain
    //     );
    // }

    // #[test]
    // fn should_not_verify_msg_if_gateway_address_does_not_match() {
    //     let (_, tx_receipt, msg) = matching_msg_and_tx_receipt();

    //     let gateway_address = EVMAddress::random();
    //     assert_eq!(
    //         verify_message(&gateway_address, &tx_receipt, &msg),
    //         Vote::NotFound
    //     );
    // }

    // #[test]
    // fn should_not_verify_msg_if_log_index_does_not_match() {
    //     let (gateway_address, tx_receipt, mut msg) = matching_msg_and_tx_receipt();

    //     msg.message_id.event_index = 0;
    //     assert_eq!(
    //         verify_message(&gateway_address, &tx_receipt, &msg),
    //         Vote::NotFound
    //     );
    //     msg.message_id.event_index = 2;
    //     assert_eq!(
    //         verify_message(&gateway_address, &tx_receipt, &msg),
    //         Vote::NotFound
    //     );
    //     msg.message_id.event_index = 3;
    //     assert_eq!(
    //         verify_message(&gateway_address, &tx_receipt, &msg),
    //         Vote::NotFound
    //     );
    // }

    // #[test]
    // fn should_not_verify_msg_if_log_index_greater_than_u32_max() {
    //     let (gateway_address, tx_receipt, mut msg) = matching_msg_and_tx_receipt();

    //     msg.message_id.event_index = u32::MAX as u64 + 1;
    //     assert_eq!(
    //         verify_message(&gateway_address, &tx_receipt, &msg),
    //         Vote::NotFound
    //     );
    // }

    // #[test]
    // fn should_not_verify_msg_if_msg_does_not_match() {
    //     let (gateway_address, tx_receipt, mut msg) = matching_msg_and_tx_receipt();

    //     msg.source_address = EVMAddress::random();
    //     assert_eq!(
    //         verify_message(&gateway_address, &tx_receipt, &msg),
    //         Vote::NotFound
    //     );
    // }

    // #[test]
    // fn should_verify_msg_if_correct() {
    //     let (gateway_address, tx_receipt, msg) = matching_msg_and_tx_receipt();

    //     assert_eq!(
    //         verify_message(&gateway_address, &tx_receipt, &msg),
    //         Vote::SucceededOnChain
    //     );
    // }

    const DOMAIN_SEPARATOR: [u8; 32] = [42; 32];
    const GATEWAY_PROGRAM_ID: Pubkey = axelar_solana_gateway::ID;

    fn fixture_rotate_verifier_set() -> (
        String,
        VerifierSetRotated,
        multisig::verifier_set::VerifierSet,
    ) {
        let base64_data = "c2lnbmVycyByb3RhdGVkXw== AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= rGbfImIlluyfNx5TfhnZEDS+uUBKCSDRAJ28Znulbgw=";
        let verifier_set = multisig::verifier_set::VerifierSet {
            signers: {
                let mut map = BTreeMap::new();
                map.insert("aabbcc".to_string(), multisig::msg::Signer {
                        weight: 500_u128.into(),
                        address: cosmwasm_std::Addr::unchecked("axelar1abc"),
                        pub_key: multisig::key::PublicKey::Ed25519(HexBinary::from_hex("036773a9d49a2a2f04b4aa8724d0f40e197570e4bb85f6b826da2a4ec25996d018").unwrap())

                    });
                map.insert("aabbccdd".to_string(), multisig::msg::Signer {
                        weight: 200_u128.into(),
                        address: cosmwasm_std::Addr::unchecked("axelar1abcaa"),
                        pub_key: multisig::key::PublicKey::Ed25519(HexBinary::from_hex("038f8504c6ec6c16f2b37897d33bdb0667da32d18c7144365a47ac934abedcc0ba").unwrap())
                    });
                map
            },
            threshold: 700_u128.into(),
            created_at: 1,
        };
        let verifier_set_hash = [
            172, 102, 223, 34, 98, 37, 150, 236, 159, 55, 30, 83, 126, 25, 217, 16, 52, 190, 185,
            64, 74, 9, 32, 209, 0, 157, 188, 102, 123, 165, 110, 12,
        ];
        let newly_created_vs = to_verifier_set(&verifier_set).unwrap();
        let expected_hash = axelar_solana_encoding::types::verifier_set::verifier_set_hash::<
            NativeHasher,
        >(&newly_created_vs, &DOMAIN_SEPARATOR)
        .unwrap();
        assert_eq!(verifier_set_hash, expected_hash);
        let event = VerifierSetRotated {
            epoch: 2_u64.into(),
            verifier_set_hash,
        };

        (base64_data.to_string(), event, verifier_set)
    }

    fn fixture_success_call_contract_tx_data() -> (UiTransactionStatusMeta, VerifierSetConfirmation)
    {
        let (base64_data, event, actual_verifier_set) = fixture_rotate_verifier_set();
        let logs = vec![
            "Program {GATEWAY_PROGRAM_ID} invoke [1]".to_string(),
            "Program log: Instruction: Rotate Signers".to_string(),
            "Program 11111111111111111111111111111111 invoke [2]".to_string(),
            "Program 11111111111111111111111111111111 success".to_string(),
            "Program data: {base_64_data}".to_string(),
            "Program {GATEWAY_PROGRAM_ID} consumed 11970 of 200000 compute units".to_string(),
            "Program {GATEWAY_PROGRAM_ID} success".to_string(),
        ];

        (
            tx_meta(logs),
            VerifierSetConfirmation {
                message_id: Base58SolanaTxSignatureAndEventIndex {
                    raw_signature: [123; 64],
                    event_index: 4,
                },
                verifier_set: actual_verifier_set,
            },
        )
    }

    fn tx_meta(logs: Vec<String>) -> UiTransactionStatusMeta {
        UiTransactionStatusMeta {
            err: None,
            status: Ok(()),
            fee: 0,
            pre_balances: vec![0],
            post_balances: vec![0],
            inner_instructions: OptionSerializer::None,
            log_messages: OptionSerializer::Some(logs),
            pre_token_balances: OptionSerializer::None,
            post_token_balances: OptionSerializer::None,
            rewards: OptionSerializer::None,
            loaded_addresses: OptionSerializer::None,
            return_data: OptionSerializer::None,
            compute_units_consumed: OptionSerializer::None,
        }
    }
}
