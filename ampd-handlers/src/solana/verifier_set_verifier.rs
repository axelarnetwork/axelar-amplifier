use std::collections::BTreeMap;

use axelar_wasm_std::voting::Vote;
use multisig::key::PublicKey;
use multisig::verifier_set::VerifierSet;
use solana_sdk::pubkey::Pubkey;
use tracing::error;

use super::GatewayEvent;
use crate::solana::types::VerifierSetConfirmation;
use crate::solana::verify;

pub fn verify_verifier_set(
    tx: &crate::solana::SolanaTransaction,
    message: &VerifierSetConfirmation,
    domain_separator: &[u8; 32],
    gateway_address: &Pubkey,
) -> Vote {
    verify(tx, &message.message_id, gateway_address, |gateway_event| {
        let GatewayEvent::VerifierSetRotated(verifier_set_rotated) = gateway_event else {
            error!("found gateway event but it's not VerifierSetRotated event");
            return false;
        };

        let incoming_verifier_set_hash = &verifier_set_rotated.verifier_set_hash;

        let Some(verifier_set) = to_verifier_set(&message.verifier_set) else {
            error!("verifier set data structure could not be parsed");
            return false;
        };

        let Ok(desired_hash) = solana_axelar_std::verifier_set::verifier_set_hash::<
            solana_axelar_std::hasher::Hasher,
        >(&verifier_set, domain_separator) else {
            error!("verifier set could not be hashed");
            return false;
        };

        &desired_hash == incoming_verifier_set_hash
    })
}

/// Transform from Axelar VerifierSet to solana_axelar_std VerifierSet
fn to_verifier_set(vs: &VerifierSet) -> Option<solana_axelar_std::VerifierSet> {
    let mut signers = BTreeMap::new();

    for (_cosmwasm_adr, signer) in vs.signers.iter() {
        let pub_key = to_pub_key(&signer.pub_key)?;
        let weight = signer.weight.u128();
        signers.insert(pub_key, weight);
    }

    let verifier_set = solana_axelar_std::verifier_set::VerifierSet {
        nonce: vs.created_at,
        signers,
        quorum: vs.threshold.u128(),
    };
    Some(verifier_set)
}

fn to_pub_key(pk: &PublicKey) -> Option<solana_axelar_std::PublicKey> {
    use solana_axelar_std::pubkey::SECP256K1_COMPRESSED_PUBKEY_LEN;

    match pk {
        PublicKey::Ecdsa(hb) => Some(solana_axelar_std::PublicKey(
            hb.to_array::<SECP256K1_COMPRESSED_PUBKEY_LEN>().ok()?,
        )),
        PublicKey::Ed25519(_) => {
            error!("Ed25519 public keys are not supported on Solana");
            // TODO should we error here instead of returning None?
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use anchor_lang::Discriminator;
    use axelar_wasm_std::msg_id::Base58SolanaTxSignatureAndEventIndex;
    use axelar_wasm_std::voting::Vote;
    use cosmwasm_std::{HexBinary, Uint128};
    use solana_axelar_gateway::events::VerifierSetRotatedEvent;
    use solana_sdk::pubkey::Pubkey;

    use super::*;

    #[test]
    fn should_not_verify_verifier_set_if_tx_id_does_not_match() {
        let (tx, mut event) = fixture_success_call_contract_tx_data();

        event.message_id.raw_signature = [0; 64];
        assert_eq!(
            verify_verifier_set(&tx, &event, &DOMAIN_SEPARATOR, &solana_axelar_gateway::ID),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_tx_failed() {
        let (mut tx, event) = fixture_success_call_contract_tx_data();

        tx.err = Some(solana_sdk::transaction::TransactionError::AccountInUse);
        assert_eq!(
            verify_verifier_set(&tx, &event, &DOMAIN_SEPARATOR, &solana_axelar_gateway::ID),
            Vote::FailedOnChain
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_gateway_address_does_not_match() {
        let (tx, event) = fixture_bad_gateway_call_contract_tx_data();

        assert_eq!(
            verify_verifier_set(&tx, &event, &DOMAIN_SEPARATOR, &solana_axelar_gateway::ID),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_log_index_does_not_match() {
        let (tx, mut event) = fixture_success_call_contract_tx_data();

        event.message_id.inner_ix_group_index = 999.try_into().unwrap(); // Use a high index that won't exist
        assert_eq!(
            verify_verifier_set(&tx, &event, &DOMAIN_SEPARATOR, &solana_axelar_gateway::ID),
            Vote::NotFound
        );
        event.message_id.inner_ix_index = 1001.try_into().unwrap(); // Another high index that won't exist
        assert_eq!(
            verify_verifier_set(&tx, &event, &DOMAIN_SEPARATOR, &solana_axelar_gateway::ID),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_log_index_greater_than_u32_max() {
        let (tx, mut event) = fixture_success_call_contract_tx_data();

        event.message_id.inner_ix_group_index = u32::MAX.try_into().unwrap(); // Use max u32 value
        event.message_id.inner_ix_index = u32::MAX.try_into().unwrap();
        assert_eq!(
            verify_verifier_set(&tx, &event, &DOMAIN_SEPARATOR, &solana_axelar_gateway::ID),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_verifier_set_does_not_match() {
        let (tx, mut event) = fixture_success_call_contract_tx_data();

        event.verifier_set.threshold = Uint128::from(50u64);
        assert_eq!(
            verify_verifier_set(&tx, &event, &DOMAIN_SEPARATOR, &solana_axelar_gateway::ID),
            Vote::NotFound
        );
    }

    #[test_log::test]
    fn should_verify_verifier_set_if_correct() {
        let (tx, event) = fixture_success_call_contract_tx_data();

        assert_eq!(
            verify_verifier_set(&tx, &event, &DOMAIN_SEPARATOR, &solana_axelar_gateway::ID),
            Vote::SucceededOnChain
        );
    }

    const DOMAIN_SEPARATOR: [u8; 32] = [42; 32];
    const RAW_SIGNATURE: [u8; 64] = [42; 64];

    const FIXTURE_VERIFIER_SET_HASH: [u8; 32] = [
        64, 41, 99, 180, 8, 232, 201, 108, 132, 236, 128, 215, 100, 34, 207, 49, 50, 255, 134, 221,
        247, 54, 229, 206, 55, 158, 119, 180, 156, 113, 114, 72,
    ];

    fn fixture_rotate_verifier_set() -> (
        String,
        VerifierSetRotatedEvent,
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
        let verifier_set_hash = FIXTURE_VERIFIER_SET_HASH;
        let newly_created_vs = to_verifier_set(&verifier_set).unwrap();
        let expected_hash = solana_axelar_std::verifier_set::verifier_set_hash::<
            solana_axelar_std::hasher::Hasher,
        >(&newly_created_vs, &DOMAIN_SEPARATOR)
        .unwrap();
        assert_eq!(verifier_set_hash, expected_hash);
        let event = VerifierSetRotatedEvent {
            epoch: solana_axelar_std::U256::from(2_u64),
            verifier_set_hash,
        };

        (base64_data.to_string(), event, verifier_set)
    }

    fn fixture_success_call_contract_tx_data(
    ) -> (crate::solana::SolanaTransaction, VerifierSetConfirmation) {
        let (_base64_data, _event, actual_verifier_set) = fixture_rotate_verifier_set();
        // Create mock CPI instruction data for VerifierSetRotated event
        let mut epoch_bytes = [0u8; 32];
        epoch_bytes[..8].copy_from_slice(&2_u64.to_le_bytes()); // Put u64 in first 8 bytes
                                                                // Convert epoch_bytes to [u64; 4] for U256::from_le_bytes
        let mut epoch_u64_array = [0u64; 4];
        for (i, chunk) in epoch_bytes.chunks_exact(8).enumerate().take(4) {
            if let Ok(bytes) = chunk.try_into() {
                epoch_u64_array[i] = u64::from_le_bytes(bytes);
            }
        }

        let verifier_set_rotated_data = VerifierSetRotatedEvent {
            epoch: solana_axelar_std::U256::from_le_bytes(epoch_bytes),
            verifier_set_hash: FIXTURE_VERIFIER_SET_HASH,
        };

        // Serialize the event with discriminators
        let mut instruction_data = Vec::new();
        instruction_data.extend_from_slice(anchor_lang::event::EVENT_IX_TAG_LE);
        instruction_data.extend_from_slice(VerifierSetRotatedEvent::DISCRIMINATOR);
        instruction_data.extend_from_slice(&borsh::to_vec(&verifier_set_rotated_data).unwrap());

        let compiled_instruction = solana_transaction_status::UiCompiledInstruction {
            program_id_index: 0,
            accounts: vec![],
            data: bs58::encode(&instruction_data).into_string(),
            stack_height: Some(2),
        };

        let instruction = solana_transaction_status::UiInstruction::Compiled(compiled_instruction);

        let inner_instructions = vec![solana_transaction_status::UiInnerInstructions {
            index: 0,
            instructions: vec![instruction],
        }];

        (
            crate::solana::SolanaTransaction {
                signature: RAW_SIGNATURE.into(),
                inner_instructions,
                err: None,
                account_keys: vec![solana_axelar_gateway::ID], // Gateway program at index 0
            },
            VerifierSetConfirmation {
                message_id: Base58SolanaTxSignatureAndEventIndex {
                    raw_signature: RAW_SIGNATURE,
                    inner_ix_group_index: 1.try_into().unwrap(), // Inner instruction group 1 (1-based)
                    inner_ix_index: 1.try_into().unwrap(), // First inner instruction (1-based)
                },
                verifier_set: actual_verifier_set,
            },
        )
    }

    fn fixture_bad_gateway_call_contract_tx_data(
    ) -> (crate::solana::SolanaTransaction, VerifierSetConfirmation) {
        let _gateway_address = Pubkey::new_unique();

        let (_base64_data, _event, actual_verifier_set) = fixture_rotate_verifier_set();

        (
            crate::solana::SolanaTransaction {
                signature: RAW_SIGNATURE.into(),
                inner_instructions: vec![],
                err: None,
                account_keys: vec![solana_axelar_gateway::ID], // Gateway program at index 0
            },
            VerifierSetConfirmation {
                message_id: Base58SolanaTxSignatureAndEventIndex {
                    raw_signature: RAW_SIGNATURE,
                    inner_ix_group_index: 1.try_into().unwrap(), // Inner instruction group 1 (1-based)
                    inner_ix_index: 1.try_into().unwrap(), // First inner instruction (1-based)
                },
                verifier_set: actual_verifier_set,
            },
        )
    }
}
