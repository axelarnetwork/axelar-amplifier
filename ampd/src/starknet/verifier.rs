use axelar_wasm_std::voting::Vote;
use cosmwasm_std::HexBinary;
use router_api::ChainName;
use starknet_core::types::Felt;
use tracing::debug;

use crate::handlers::starknet_verify_msg::Message;
use crate::handlers::starknet_verify_verifier_set::VerifierSetConfirmation;
use crate::types::starknet::events::contract_call::ContractCallEvent;
use crate::types::starknet::events::signers_rotated::SignersRotatedEvent;

/// Attempts to fetch the tx provided in `axl_msg.tx_id`.
/// If successful, extracts and parses the ContractCall event
/// and compares it to the message from the relayer (via PollStarted event).
/// Also checks if the source_gateway_address with which
/// the voting verifier has been instantiated is the same address from
/// which the ContractCall event is coming.
pub fn verify_msg(
    starknet_event: &ContractCallEvent,
    msg: &Message,
    source_gateway_address: &str,
) -> Vote {
    if *starknet_event == *msg && starknet_event.from_contract_addr == source_gateway_address {
        Vote::SucceededOnChain
    } else {
        Vote::NotFound
    }
}

impl PartialEq<Message> for ContractCallEvent {
    fn eq(&self, axl_msg: &Message) -> bool {
        let matches_destination_chain = match ChainName::try_from(self.destination_chain.as_ref()) {
            Ok(chain) => axl_msg.destination_chain == chain,
            Err(e) => {
                debug!(error = ?e, "failed to parse destination chain");
                false
            }
        };

        matches_destination_chain
            && Felt::from(axl_msg.source_address.clone()) == self.source_address
            && axl_msg.destination_address == self.destination_address
            && axl_msg.payload_hash == self.payload_hash
    }
}

pub fn verify_verifier_set(
    event: &SignersRotatedEvent,
    confirmation: &VerifierSetConfirmation,
    source_gateway_address: &str,
) -> Vote {
    if event == confirmation && event.from_address == source_gateway_address {
        Vote::SucceededOnChain
    } else {
        Vote::NotFound
    }
}

impl PartialEq<VerifierSetConfirmation> for SignersRotatedEvent {
    fn eq(&self, confirmation: &VerifierSetConfirmation) -> bool {
        let expected = &confirmation.verifier_set;

        // Convert and sort expected signers
        let mut expected_signers = expected
            .signers
            .values()
            .filter_map(|signer| match &signer.pub_key {
                multisig::key::PublicKey::Ecdsa(pubkey) => {
                    Some((pubkey.clone(), signer.weight.u128()))
                }
                _ => None,
            })
            .collect::<Vec<_>>();

        if expected_signers.is_empty() {
            return false;
        }
        expected_signers.sort();

        // Convert and sort actual signers from the event
        let mut actual_signers = self
            .signers
            .signers
            .iter()
            .map(|signer| {
                (
                    HexBinary::from_hex(&signer.signer)
                        .expect("signer should create a HexBinary validly"),
                    signer.weight,
                )
            })
            .collect::<Vec<_>>();
        actual_signers.sort();

        // Compare signers, threshold, and created_at timestamp
        actual_signers == expected_signers
            && self.signers.threshold == expected.threshold.u128()
            && self.epoch == expected.created_at
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::str::FromStr;

    use axelar_wasm_std::msg_id::FieldElementAndEventIndex;
    use axelar_wasm_std::voting::Vote;
    use cosmwasm_std::{Addr, HexBinary, Uint128};
    use ethers_core::types::H256;
    use multisig::msg::Signer;
    use multisig::verifier_set::VerifierSet;
    use router_api::chain_name;
    use starknet_checked_felt::CheckedFelt;
    use starknet_core::types::Felt;

    use super::verify_msg;
    use crate::handlers::starknet_verify_msg::Message;
    use crate::handlers::starknet_verify_verifier_set::VerifierSetConfirmation;
    use crate::starknet::verifier::verify_verifier_set;
    use crate::types::starknet::events::contract_call::ContractCallEvent;
    use crate::types::starknet::events::signers_rotated::{
        Signer as StarknetSigner, SignersRotatedEvent, WeightedSigners,
    };

    // "hello" as payload
    // "hello" as destination address
    // "some_contract_address" as source address
    // "destination_chain" as destination_chain
    fn mock_valid_event() -> ContractCallEvent {
        ContractCallEvent {
            from_contract_addr: String::from(
                "0x035410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439e",
            ),
            destination_address: String::from("destination_address"),
            destination_chain: String::from("ethereum"),
            source_address: Felt::from_str(
                "0x00b3ff441a68610b30fd5e2abbf3a1548eb6ba6f3559f2862bf2dc757e5828ca",
            )
            .unwrap(),
            payload_hash: H256::from_slice(&[
                28, 138, 255, 149, 6, 133, 194, 237, 75, 195, 23, 79, 52, 114, 40, 123, 86, 217,
                81, 123, 156, 148, 129, 39, 49, 154, 9, 167, 163, 109, 234, 200,
            ]),
        }
    }

    fn mock_valid_message() -> Message {
        Message {
            message_id: FieldElementAndEventIndex {
                tx_hash: CheckedFelt::from_str(
                    "0x0000000000000000000000000000000000000000000000000000000000000001",
                )
                .unwrap(),
                event_index: 0,
            },
            destination_address: String::from("destination_address"),
            destination_chain: chain_name!("ethereum"),
            source_address: CheckedFelt::from_str(
                "0x00b3ff441a68610b30fd5e2abbf3a1548eb6ba6f3559f2862bf2dc757e5828ca",
            )
            .unwrap(),
            payload_hash: H256::from_slice(&[
                28, 138, 255, 149, 6, 133, 194, 237, 75, 195, 23, 79, 52, 114, 40, 123, 86, 217,
                81, 123, 156, 148, 129, 39, 49, 154, 9, 167, 163, 109, 234, 200,
            ]),
        }
    }

    #[test]
    fn shoud_fail_different_source_gw() {
        assert_eq!(
            verify_msg(
                &mock_valid_event(),
                &mock_valid_message(),
                &String::from("different"),
            ),
            Vote::NotFound
        )
    }

    #[test]
    fn shoud_fail_different_event_fields() {
        let msg = mock_valid_message();
        let source_gw_address =
            String::from("0x035410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439e");

        let mut event = mock_valid_event();
        event.destination_address = String::from("different");
        assert_eq!(verify_msg(&event, &msg, &source_gw_address), Vote::NotFound);

        let mut event = { mock_valid_event() };
        event.destination_chain = String::from("different");
        assert_eq!(verify_msg(&event, &msg, &source_gw_address), Vote::NotFound);

        let mut event = { mock_valid_event() };
        event.source_address = Felt::THREE;
        assert_eq!(verify_msg(&event, &msg, &source_gw_address), Vote::NotFound);

        let mut event = { mock_valid_event() };
        event.payload_hash = H256::from_slice(&[
            28u8, 138, 255, 149, 6, 133, 194, 237, 75, 195, 23, 79, 52, 114, 40, 123, 86, 217, 81,
            123, 156, 148, 129, 39, 49, 154, 9, 167, 163, 109, 234,
            1, // last byte is different
        ]);
        assert_eq!(verify_msg(&event, &msg, &source_gw_address), Vote::NotFound);
    }

    #[test]
    fn shoud_fail_different_msg_fields() {
        let event = mock_valid_event();
        let source_gw_address =
            String::from("0x035410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439e");

        let mut msg = mock_valid_message();
        msg.destination_address = String::from("different");
        assert_eq!(verify_msg(&event, &msg, &source_gw_address), Vote::NotFound);

        let mut msg = { mock_valid_message() };
        msg.destination_chain = chain_name!("avalanche");
        assert_eq!(verify_msg(&event, &msg, &source_gw_address), Vote::NotFound);

        let mut msg = { mock_valid_message() };
        msg.source_address = CheckedFelt::try_from(&Felt::THREE.to_bytes_be()).unwrap();
        assert_eq!(verify_msg(&event, &msg, &source_gw_address), Vote::NotFound);

        let mut msg = { mock_valid_message() };
        msg.payload_hash = H256::from_slice(&[
            28u8, 138, 255, 149, 6, 133, 194, 237, 75, 195, 23, 79, 52, 114, 40, 123, 86, 217, 81,
            123, 156, 148, 129, 39, 49, 154, 9, 167, 163, 109, 234,
            1, // last byte is different
        ]);
        assert_eq!(verify_msg(&event, &msg, &source_gw_address), Vote::NotFound);
    }

    #[test]
    fn shoud_verify_event() {
        assert_eq!(
            verify_msg(
                &mock_valid_event(),
                &mock_valid_message(),
                &String::from("0x035410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439e"),
            ),
            Vote::SucceededOnChain
        )
    }

    #[test]
    fn shoud_verify_event_if_chain_uses_different_casing() {
        let msg = mock_valid_message();
        let mut event = mock_valid_event();
        event.destination_chain = msg.destination_chain.to_string().to_uppercase();

        assert_eq!(
            verify_msg(
                &event,
                &msg,
                &String::from("0x035410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439e"),
            ),
            Vote::SucceededOnChain
        )
    }

    /// Verifier set - signers rotated
    fn mock_valid_confirmation_signers_rotated() -> VerifierSetConfirmation {
        VerifierSetConfirmation {
            verifier_set: mock_valid_verifier_set_signers_rotated(),
            message_id: FieldElementAndEventIndex {
                tx_hash: CheckedFelt::try_from(&[0_u8; 32]).unwrap(),
                event_index: 0,
            },
        }
    }

    fn mock_valid_verifier_set_signers_rotated() -> VerifierSet {
        let signers = vec![Signer {
            address: Addr::unchecked("axelarvaloper1x86a8prx97ekkqej2x636utrdu23y8wupp9gk5"),
            weight: Uint128::from(10u128),
            pub_key: multisig::key::PublicKey::Ecdsa(
                HexBinary::from_hex(
                    "03d123ce370b163acd576be0e32e436bb7e63262769881d35fa3573943bf6c6f81",
                )
                .unwrap(),
            ),
        }];

        let mut btree_signers = BTreeMap::new();
        for signer in signers {
            btree_signers.insert(signer.address.clone().to_string(), signer);
        }

        VerifierSet {
            signers: btree_signers,
            threshold: Uint128::one(),
            created_at: 1,
        }
    }

    fn mock_valid_event_signers_rotated() -> SignersRotatedEvent {
        SignersRotatedEvent {
            // should be the same as the source gw address
            from_address: String::from(
                "0x035410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439e",
            ),
            epoch: 1,
            signers_hash: [8_u8; 32],
            signers: WeightedSigners {
                signers: vec![StarknetSigner {
                    signer: String::from(
                        "03d123ce370b163acd576be0e32e436bb7e63262769881d35fa3573943bf6c6f81",
                    ),
                    weight: Uint128::from(10u128).into(),
                }],
                threshold: Uint128::one().into(),
                nonce: [7_u8; 32],
            },
        }
    }

    fn mock_second_valid_event_signers_rotated() -> SignersRotatedEvent {
        SignersRotatedEvent {
            from_address: String::from(
                "0x035410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439e",
            ),
            epoch: 1,
            signers_hash: [8_u8; 32],
            signers: WeightedSigners {
                signers: vec![StarknetSigner {
                    signer: String::from(
                        "028584592624e742ba154c02df4c0b06e4e8a957ba081083ea9fe5309492aa6c7b",
                    ),
                    weight: Uint128::from(10u128).into(),
                }],
                threshold: Uint128::one().into(),
                nonce: [7_u8; 32],
            },
        }
    }

    #[test]
    fn should_verify_verifier_set() {
        let source_gw_address =
            String::from("0x035410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439e");
        let confirmation = mock_valid_confirmation_signers_rotated();
        let event = mock_valid_event_signers_rotated();

        assert_eq!(
            verify_verifier_set(&event, &confirmation, &source_gw_address),
            Vote::SucceededOnChain
        );
    }

    #[test]
    fn shoud_not_verify_verifier_set_if_signers_mismatch() {
        let source_gw_address =
            String::from("0x035410be6f4bf3f67f7c1bb4a93119d9d410b2f981bfafbf5dbbf5d37ae7439e");
        let event = mock_second_valid_event_signers_rotated();
        let confirmation = mock_valid_confirmation_signers_rotated();

        assert_eq!(
            verify_verifier_set(&event, &confirmation, &source_gw_address),
            Vote::NotFound
        );
    }
}
