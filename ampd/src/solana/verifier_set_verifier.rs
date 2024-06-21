use axelar_message_primitives::Address;
use axelar_wasm_std::voting::Vote;
use hex::ToHex;
use multisig::key::PublicKey;

use crate::handlers::solana_verify_verifier_set::VerifierSetConfirmation;
use solana_transaction_status::{
    option_serializer::OptionSerializer, EncodedConfirmedTransactionWithStatusMeta,
};
use thiserror::Error;
use tracing::error;

use gmp_gateway::events::GatewayEvent;

#[derive(Error, Debug, PartialEq)]
pub enum VerificationError {
    #[error("Failed to parse tx log messages")]
    NoLogMessages,
    #[error("Tried to get gateway event from program logs, but couldn't find anything.")]
    NoGatewayEventFound,
}

type Result<T> = std::result::Result<T, VerificationError>;

pub fn parse_gateway_event(tx: &EncodedConfirmedTransactionWithStatusMeta) -> Result<GatewayEvent> {
    let Some(meta) = &tx.transaction.meta else {
        return Err(VerificationError::NoLogMessages);
    };

    let OptionSerializer::Some(log_messages) = &meta.log_messages else {
        return Err(VerificationError::NoLogMessages);
    };

    log_messages
        .iter()
        .find_map(GatewayEvent::parse_log)
        .ok_or(VerificationError::NoGatewayEventFound)
}

#[tracing::instrument(name = "solana_verify_verifier_set")]
pub fn verify_verifier_set(
    verifier_set_conf: &VerifierSetConfirmation,
    solana_signers: &[Address],
    solana_weights: &[u128],
    solana_quorum: u128,
) -> Vote {
    let tx_id = &verifier_set_conf.tx_id;
    let verifier_set = &verifier_set_conf.verifier_set;
    let verifier_set_threshold = verifier_set.threshold.u128();

    if solana_signers.len() != solana_weights.len() {
        error!(
            tx_id,
            solana_signers_count = solana_signers.len(),
            solana_weights_count = solana_weights.len(),
            "Signers length do not match in solana onchain data.",
        );
        return Vote::FailedOnChain;
    }

    if verifier_set_threshold != solana_quorum {
        error!(
            tx_id,
            axelar_threshold = verifier_set_threshold,
            solana_quorum,
            "Verifier set threshold do not match."
        );
        return Vote::FailedOnChain;
    }

    for (solana_addr, solana_weight) in solana_signers.iter().zip(solana_weights.iter()) {
        let solana_addr_hex = solana_addr.encode_hex::<String>();
        let Some((addr, signer)) = verifier_set.signers.get_key_value(&solana_addr_hex) else {
            error!(
                tx_id,
                solana_addr_hex, "Lookup for solana signer address failed on axelar verifier set",
            );
            return Vote::FailedOnChain;
        };
        let signer_address = signer.address.to_string();
        if *addr != signer_address {
            error!(
                tx_id,
                verifier_set_map_key=addr,
                verifier_set_inner_signer_address=signer_address,
                "Axelar verifier set has inconsistencies. Map key (Address) is different than the inner signer address.",
            );
            return Vote::FailedOnChain;
        }
        let signer_pub_key = match &signer.pub_key {
            PublicKey::Ecdsa(hb) | PublicKey::Ed25519(hb) => hb,
        };
        if solana_addr.as_ref() != signer_pub_key.as_slice() {
            let signer_pub_key_hex = signer.pub_key.encode_hex::<String>();
            error!(
                tx_id,
                solana_addr_hex,
                signer_pub_key_hex,
                "Solana address is different than Axelar signer public key.",
            );
            return Vote::FailedOnChain;
        }

        if *solana_weight != signer.weight.u128() {
            error!(
                tx_id,
                solana_addr_hex,
                solana_weight,
                axelar_signer_weight = signer.weight.u128(),
                "Signer weight differs",
            );
            return Vote::FailedOnChain;
        }
    }
    Vote::SucceededOnChain
}

#[cfg(test)]
mod tests {

    use cosmwasm_std::{Addr, HexBinary};
    use multisig::{
        key::{KeyType, PublicKey},
        test::common::{build_verifier_set, TestSigner},
    };

    use super::*;

    #[test]
    fn test_verifier_test_verification_ok() {
        let (verifier_set_conf, sol_signers, sol_weights, sol_quorum) =
            matching_verifier_set_and_sol_data();

        let vote = verify_verifier_set(&verifier_set_conf, &sol_signers, &sol_weights, sol_quorum);

        assert_eq!(Vote::SucceededOnChain, vote);
    }

    #[test]
    fn test_verifier_test_verification_fails_due_to_different_threshold() {
        let (verifier_set_conf, sol_signers, sol_weights, mut sol_quorum) =
            matching_verifier_set_and_sol_data();

        sol_quorum += 1;

        let vote = verify_verifier_set(&verifier_set_conf, &sol_signers, &sol_weights, sol_quorum);

        assert_eq!(Vote::FailedOnChain, vote);
    }

    #[test]
    fn test_verifier_test_verification_fails_due_to_different_weights_vec_len() {
        let (verifier_set_conf, sol_signers, mut sol_weights, sol_quorum) =
            matching_verifier_set_and_sol_data();

        sol_weights.push(1);

        let vote = verify_verifier_set(&verifier_set_conf, &sol_signers, &sol_weights, sol_quorum);

        assert_eq!(Vote::FailedOnChain, vote);
    }

    #[test]
    fn test_verifier_test_verification_fails_due_to_missing_signer() {
        let (verifier_set_conf, mut sol_signers, sol_weights, sol_quorum) =
            matching_verifier_set_and_sol_data();

        sol_signers.pop().unwrap();

        let vote = verify_verifier_set(&verifier_set_conf, &sol_signers, &sol_weights, sol_quorum);

        assert_eq!(Vote::FailedOnChain, vote);
    }

    #[test]
    fn test_verifier_test_verification_fails_due_to_different_signer_set_address() {
        let (mut verifier_set_conf, sol_signers, sol_weights, sol_quorum) =
            matching_verifier_set_and_sol_data();

        let signer = verifier_set_conf
            .verifier_set
            .signers
            .get_mut(sol_signers.get(1).unwrap().encode_hex::<String>().as_str())
            .unwrap();
        signer.address =
            Addr::unchecked("ha ! a different address in the signer set address field");

        let vote = verify_verifier_set(&verifier_set_conf, &sol_signers, &sol_weights, sol_quorum);

        assert_eq!(Vote::FailedOnChain, vote);
    }

    #[test]
    fn test_verifier_test_verification_fails_due_to_different_signer_set_pubkey() {
        let (mut verifier_set_conf, sol_signers, sol_weights, sol_quorum) =
            matching_verifier_set_and_sol_data();

        let signer = verifier_set_conf
            .verifier_set
            .signers
            .get_mut(sol_signers.get(1).unwrap().encode_hex::<String>().as_str())
            .unwrap();
        signer.pub_key = PublicKey::Ecdsa(HexBinary::from_hex("d9e1eb2b47cb8b7c1c2a5a32f6fa6c57d0e6fdd53eaa8c76fe7f0b3b390cfb3c40f258e476f2ca0e6a7ca2622ea23afe7bd1f873448e01eed86cd6446a403f35").unwrap());

        let vote = verify_verifier_set(&verifier_set_conf, &sol_signers, &sol_weights, sol_quorum);

        assert_eq!(Vote::FailedOnChain, vote);
    }

    #[test]
    fn test_verifier_test_verification_fails_due_to_different_signer_weights() {
        let (verifier_set_conf, sol_signers, mut sol_weights, sol_quorum) =
            matching_verifier_set_and_sol_data();

        *sol_weights.get_mut(1).unwrap() = 666;

        let vote = verify_verifier_set(&verifier_set_conf, &sol_signers, &sol_weights, sol_quorum);

        assert_eq!(Vote::FailedOnChain, vote);
    }

    fn matching_verifier_set_and_sol_data(
    ) -> (VerifierSetConfirmation, Vec<Address>, Vec<u128>, u128) {
        let verifier_set = build_verifier_set(KeyType::Ecdsa, &signers());

        let sol_signers = verifier_set
            .signers
            .values()
            .map(|v| Address::try_from(v.address.as_str()).unwrap())
            .collect();
        let sol_weights = verifier_set
            .signers
            .values()
            .map(|v| v.weight.u128())
            .collect::<Vec<_>>();
        let sol_quorum = verifier_set.threshold.u128();

        let verifier_set_confirmation = VerifierSetConfirmation {
            tx_id: String::from("90af"),
            event_index: 1,
            verifier_set,
        };

        (
            verifier_set_confirmation,
            sol_signers,
            sol_weights,
            sol_quorum,
        )
    }

    fn signers() -> Vec<TestSigner> {
        // This data is the same as ecdsa_test_data::signers() , but we are replacing the address with the
        // same value of the public key.
        vec![
            TestSigner {
                address: Addr::unchecked("025e0231bfad810e5276e2cf9eb2f3f380ce0bdf6d84c3b6173499d3ddcc008856"),
                pub_key: HexBinary::from_hex("025e0231bfad810e5276e2cf9eb2f3f380ce0bdf6d84c3b6173499d3ddcc008856")
            .unwrap(),
                signature: HexBinary::from_hex("d7822dd89b9df02d64b91f69cff5811dfd4de16b792d9c6054b417c733bbcc542c1e504c8a1dffac94b5828a93e33a6b45d1bf59b2f9f28ffa56b8398d68a1c5")
            .unwrap(),
                signed_address: HexBinary::from_hex(
                    "d9e1eb2b47cb8b7c1c2a5a32f6fa6c57d0e6fdd53eaa8c76fe7f0b3b390cfb3c40f258e476f2ca0e6a7ca2622ea23afe7bd1f873448e01eed86cd6446a403f36",
                )
                .unwrap(),
            },
            TestSigner {
                address: Addr::unchecked("036ff6f4b2bc5e08aba924bd8fd986608f3685ca651a015b3d9d6a656de14769fe"),
                pub_key: HexBinary::from_hex("036ff6f4b2bc5e08aba924bd8fd986608f3685ca651a015b3d9d6a656de14769fe")
            .unwrap(),
                signature: HexBinary::from_hex("a7ec5d1c15e84ba4b5da23fee49d77c5c81b3b1859411d1ef8193bf5a39783c76813e4cf4e1e1bfa0ea19c9f5b61d25ce978da137f3adb1730cba3d842702e72")
            .unwrap(),
                signed_address: HexBinary::from_hex(
                    "008ca739eaddd22856c30690bf9a85f16ea77784494ad01111fded80327c57c84e021608cd890341883de1ac0fcf31330243b91b22c4751542ac47115f2f4e2c",
                )
                .unwrap(),
            },
            TestSigner {
                address: Addr::unchecked("03686cbbef9f9e9a5c852883cb2637b55fc76bee6ee6a3ff636e7bea2e41beece4"),
                pub_key: HexBinary::from_hex("03686cbbef9f9e9a5c852883cb2637b55fc76bee6ee6a3ff636e7bea2e41beece4")
            .unwrap(),
                signature: HexBinary::from_hex("d1bc22fd89d97dfe4091c73d2002823ca9ab29b742ae531d2560bf2abafb313f7d2c3263d09d9aa72f01ed1d49046e39f6513ea61241fd59cc53d02fc4222351")
            .unwrap(),
                signed_address: HexBinary::from_hex(
                    "1df5a371c27772874b706dbbb41e0bc67f688b301d3c2d269e45c43389fa43b6328c32686f42242b0cdb05b3b955ce3106393d6e509bf0373340482182c865cc",
                )
                .unwrap(),
            },
        ]
    }
}
