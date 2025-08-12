use std::collections::BTreeMap;

use axelar_solana_encoding::hasher::NativeHasher;
use axelar_solana_encoding::types::verifier_set::verifier_set_hash;
use axelar_solana_gateway::processor::{GatewayEvent, VerifierSetRotated};
use axelar_wasm_std::voting::Vote;
use multisig::key::PublicKey;
use multisig::verifier_set::VerifierSet;
use solana_sdk::signature::Signature;
use solana_transaction_status::UiTransactionStatusMeta;
use tracing::error;

use crate::handlers::solana_verify_verifier_set::VerifierSetConfirmation;
use crate::solana::verify;

pub fn verify_verifier_set(
    tx: (&Signature, &UiTransactionStatusMeta),
    message: &VerifierSetConfirmation,
    domain_separator: &[u8; 32],
) -> Vote {
    verify(tx, &message.message_id, |gateway_event| {
        let GatewayEvent::VerifierSetRotated(VerifierSetRotated {
            verifier_set_hash: incoming_verifier_set_hash,
            epoch: _,
        }) = gateway_event
        else {
            error!("found gateway event but it's not VerifierSetRotated event");
            return false;
        };

        let Some(verifier_set) = to_verifier_set(&message.verifier_set) else {
            error!("verifier set data structure could not be parsed");
            return false;
        };

        let Ok(desired_hash) = verifier_set_hash::<NativeHasher>(&verifier_set, domain_separator)
        else {
            error!("verifier set could not be hashed");
            return false;
        };

        &desired_hash == incoming_verifier_set_hash
    })
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
    use axelar_solana_encoding::types::pubkey::{
        ED25519_PUBKEY_LEN, SECP256K1_COMPRESSED_PUBKEY_LEN,
    };
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
    use std::collections::BTreeMap;

    use axelar_solana_gateway::processor::VerifierSetRotated;
    use axelar_wasm_std::msg_id::Base58SolanaTxSignatureAndEventIndex;
    use axelar_wasm_std::voting::Vote;
    use cosmwasm_std::{HexBinary, Uint128};
    use solana_sdk::pubkey::Pubkey;
    use solana_transaction_status::option_serializer::OptionSerializer;
    use solana_transaction_status::UiTransactionStatusMeta;

    use super::*;

    #[test]
    fn should_not_verify_verifier_set_if_tx_id_does_not_match() {
        let ((signature, tx), mut event) = fixture_success_call_contract_tx_data();

        event.message_id.raw_signature = [0; 64];
        assert_eq!(
            verify_verifier_set((&signature, &tx), &event, &DOMAIN_SEPARATOR),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_tx_failed() {
        let ((signature, mut tx), event) = fixture_success_call_contract_tx_data();

        tx.err = Some(solana_sdk::transaction::TransactionError::AccountInUse);
        assert_eq!(
            verify_verifier_set((&signature, &tx), &event, &DOMAIN_SEPARATOR),
            Vote::FailedOnChain
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_gateway_address_does_not_match() {
        let ((signature, tx), event) = fixture_bad_gateway_call_contract_tx_data();

        assert_eq!(
            verify_verifier_set((&signature, &tx), &event, &DOMAIN_SEPARATOR),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_log_index_does_not_match() {
        let ((signature, tx), mut event) = fixture_success_call_contract_tx_data();

        event.message_id.event_index -= 1;
        assert_eq!(
            verify_verifier_set((&signature, &tx), &event, &DOMAIN_SEPARATOR),
            Vote::NotFound
        );
        event.message_id.event_index += 2;
        assert_eq!(
            verify_verifier_set((&signature, &tx), &event, &DOMAIN_SEPARATOR),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_log_index_greater_than_u32_max() {
        let ((signature, tx), mut event) = fixture_success_call_contract_tx_data();

        event.message_id.event_index = u32::MAX as u64 + 1;
        assert_eq!(
            verify_verifier_set((&signature, &tx), &event, &DOMAIN_SEPARATOR),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_verifier_set_does_not_match() {
        let ((signature, tx), mut event) = fixture_success_call_contract_tx_data();

        event.verifier_set.threshold = Uint128::from(50u64);
        assert_eq!(
            verify_verifier_set((&signature, &tx), &event, &DOMAIN_SEPARATOR),
            Vote::NotFound
        );
    }

    #[test_log::test]
    fn should_verify_verifier_set_if_correct() {
        let ((signature, tx), event) = fixture_success_call_contract_tx_data();

        assert_eq!(
            verify_verifier_set((&signature, &tx), &event, &DOMAIN_SEPARATOR),
            Vote::SucceededOnChain
        );
    }

    const DOMAIN_SEPARATOR: [u8; 32] = [42; 32];
    const GATEWAY_PROGRAM_ID: Pubkey = axelar_solana_gateway::ID;
    const RAW_SIGNATURE: [u8; 64] = [42; 64];

    fn fixture_rotate_verifier_set() -> (
        String,
        VerifierSetRotated,
        multisig::verifier_set::VerifierSet,
    ) {
        let base64_data = "c2lnbmVycyByb3RhdGVkXw== AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= rGbfImIlluyfNx5TfhnZEDS+uUBKCSDRAJ28Znulbgw=";
        let verifier_set = multisig::verifier_set::VerifierSet {
            signers: {
                let mut map = BTreeMap::new();
                map.insert(
                    "aabbcc".to_string(),
                    multisig::msg::Signer {
                        weight: 500_u128.into(),
                        address: cosmwasm_std::Addr::unchecked("axelar1abc"),
                        pub_key: multisig::key::PublicKey::Ecdsa(HexBinary::from_hex(
                    "036773a9d49a2a2f04b4aa8724d0f40e197570e4bb85f6b826da2a4ec25996d018",
                )
                .unwrap()),
                    },
                );
                map.insert("aabbccdd".to_string(), multisig::msg::Signer {
                        weight: 200_u128.into(),
                        address: cosmwasm_std::Addr::unchecked("axelar1abcaa"),
                        pub_key: multisig::key::PublicKey::Ecdsa(HexBinary::from_hex("038f8504c6ec6c16f2b37897d33bdb0667da32d18c7144365a47ac934abedcc0ba").unwrap())
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

    fn fixture_success_call_contract_tx_data() -> (
        (Signature, UiTransactionStatusMeta),
        VerifierSetConfirmation,
    ) {
        let (base64_data, _event, actual_verifier_set) = fixture_rotate_verifier_set();
        let logs = vec![
            format!("Program {GATEWAY_PROGRAM_ID} invoke [1]"),
            "Program log: Instruction: Rotate Signers".to_string(),
            "Program 11111111111111111111111111111111 invoke [2]".to_string(),
            "Program 11111111111111111111111111111111 success".to_string(),
            format!("Program data: {base64_data}"),
            format!("Program {GATEWAY_PROGRAM_ID} consumed 11970 of 200000 compute units"),
            format!("Program {GATEWAY_PROGRAM_ID} success"),
        ];

        (
            (RAW_SIGNATURE.into(), tx_meta(logs)),
            VerifierSetConfirmation {
                message_id: Base58SolanaTxSignatureAndEventIndex {
                    raw_signature: RAW_SIGNATURE,
                    event_index: 4,
                },
                verifier_set: actual_verifier_set,
            },
        )
    }

    fn fixture_bad_gateway_call_contract_tx_data() -> (
        (Signature, UiTransactionStatusMeta),
        VerifierSetConfirmation,
    ) {
        let gateway_address = Pubkey::new_unique();

        let (base64_data, _event, actual_verifier_set) = fixture_rotate_verifier_set();
        let logs = vec![
            format!("Program {gateway_address} invoke [1]"),
            "Program log: Instruction: Rotate Signers".to_string(),
            "Program 11111111111111111111111111111111 invoke [2]".to_string(),
            "Program 11111111111111111111111111111111 success".to_string(),
            format!("Program data: {base64_data}"),
            format!("Program {gateway_address} consumed 11970 of 200000 compute units"),
            format!("Program {gateway_address} success"),
        ];

        (
            (RAW_SIGNATURE.into(), tx_meta(logs)),
            VerifierSetConfirmation {
                message_id: Base58SolanaTxSignatureAndEventIndex {
                    raw_signature: RAW_SIGNATURE,
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
