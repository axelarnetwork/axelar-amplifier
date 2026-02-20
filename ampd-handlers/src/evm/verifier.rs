use ampd::types::EVMAddress;
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::voting::Vote;
use ethers_contract::EthLogDecode;
use ethers_core::types::{Log, Transaction, TransactionReceipt, H160, H256};
use event_verifier_api::evm::{Event, EvmEvent, TransactionDetails};
use evm_gateway::{IAxelarAmplifierGatewayEvents, WeightedSigners};
use tracing::debug;

use crate::evm::types::{Message, VerifierSetConfirmation};

struct IAxelarGatewayEventsWithLog<'a>(&'a Log, IAxelarAmplifierGatewayEvents);

impl PartialEq<IAxelarGatewayEventsWithLog<'_>> for &Message {
    fn eq(&self, other: &IAxelarGatewayEventsWithLog<'_>) -> bool {
        let IAxelarGatewayEventsWithLog(log, event) = other;

        match event {
            IAxelarAmplifierGatewayEvents::ContractCallFilter(event) => {
                let matches_destination_chain =
                    match ChainName::try_from(event.destination_chain.as_ref()) {
                        Ok(chain) => self.destination_chain == chain,
                        Err(e) => {
                            debug!(error = ?e, "failed to parse destination chain");
                            false
                        }
                    };

                matches_destination_chain
                    && log.transaction_hash == Some(self.message_id.tx_hash.into())
                    && event.sender == self.source_address
                    && event.destination_contract_address == self.destination_address
                    && event.payload_hash == self.payload_hash.as_bytes()
            }
            _ => false,
        }
    }
}

impl PartialEq<IAxelarGatewayEventsWithLog<'_>> for &VerifierSetConfirmation {
    fn eq(&self, other: &IAxelarGatewayEventsWithLog<'_>) -> bool {
        let IAxelarGatewayEventsWithLog(log, event) = other;
        match event {
            IAxelarAmplifierGatewayEvents::SignersRotatedFilter(event) => {
                let weighted_signers = match WeightedSigners::try_from(&self.verifier_set) {
                    Ok(signers) => signers,
                    Err(_) => return false,
                };

                log.transaction_hash == Some(self.message_id.tx_hash.into())
                    && event.signers_hash == weighted_signers.hash()
                    && event.signers == weighted_signers.abi_encode()
            }
            _ => false,
        }
    }
}

fn has_failed(tx_receipt: &TransactionReceipt) -> bool {
    tx_receipt.status == Some(0u64.into())
}

fn event<'a>(
    gateway_address: &EVMAddress,
    tx_receipt: &'a TransactionReceipt,
    log_index: u64,
) -> Option<IAxelarGatewayEventsWithLog<'a>> {
    let log_index: usize = usize::try_from(log_index).ok()?;

    tx_receipt
        .logs
        .get(log_index)
        .filter(|log| log.address == *gateway_address)
        .and_then(
            |log| match IAxelarAmplifierGatewayEvents::decode_log(&log.clone().into()) {
                Ok(event) => Some(IAxelarGatewayEventsWithLog(log, event)),
                Err(_) => None,
            },
        )
}

fn verify<'a, V>(
    gateway_address: &EVMAddress,
    tx_receipt: &'a TransactionReceipt,
    to_verify: V,
    expected_transaction_hash: H256,
    expected_event_index: u64,
) -> Vote
where
    V: PartialEq<IAxelarGatewayEventsWithLog<'a>>,
{
    let found_event = event(gateway_address, tx_receipt, expected_event_index);

    // Only return FailedOnChain if we can verify the tx involved our gateway
    if has_failed(tx_receipt) {
        return if found_event.is_some() {
            Vote::FailedOnChain
        } else {
            Vote::NotFound
        };
    }

    match found_event {
        Some(event)
            if tx_receipt.transaction_hash == expected_transaction_hash && to_verify == event =>
        {
            Vote::SucceededOnChain
        }
        _ => Vote::NotFound,
    }
}

pub fn verify_message(
    gateway_address: &EVMAddress,
    tx_receipt: &TransactionReceipt,
    msg: &Message,
) -> Vote {
    verify(
        gateway_address,
        tx_receipt,
        msg,
        msg.message_id.tx_hash.into(),
        msg.message_id.event_index,
    )
}

pub fn verify_verifier_set(
    gateway_address: &EVMAddress,
    tx_receipt: &TransactionReceipt,
    confirmation: &VerifierSetConfirmation,
) -> Vote {
    verify(
        gateway_address,
        tx_receipt,
        confirmation,
        confirmation.message_id.tx_hash.into(),
        confirmation.message_id.event_index,
    )
}

pub fn verify_events(
    tx_receipt: &TransactionReceipt,
    tx: Option<&Transaction>,
    event_data: &EvmEvent,
) -> Vote {
    let expected_tx_hash: H256 = event_data.transaction_hash.to_array().into();

    if tx_receipt.transaction_hash != expected_tx_hash {
        return Vote::NotFound;
    }

    // Verify transaction details if provided
    if let Some(expected_details) = &event_data.transaction_details {
        if !tx.is_some_and(|tx| verify_transaction_details(tx, expected_details)) {
            return Vote::NotFound;
        }
    }

    // An empty events list would vacuously match any transaction.
    // Require at least one event to prevent verifying arbitrary transactions.
    if event_data.events.is_empty() {
        return Vote::NotFound;
    }

    // Verify events match the logs in the transaction receipt
    let events_match = verify_events_match_logs(&tx_receipt.logs, &event_data.events);

    // Only return FailedOnChain if we can verify the tx involved our gateway
    if has_failed(tx_receipt) {
        return if events_match {
            Vote::FailedOnChain
        } else {
            Vote::NotFound
        };
    }

    if events_match {
        Vote::SucceededOnChain
    } else {
        Vote::NotFound
    }
}

fn verify_transaction_details(
    actual_tx: &Transaction,
    expected_details: &TransactionDetails,
) -> bool {
    let expected_from: H160 = expected_details.from.to_array().into();
    let expected_to: Option<H160> = expected_details
        .to
        .as_ref()
        .map(|addr| addr.to_array().into());

    let expected_value =
        ethers_core::types::U256::from_big_endian(&expected_details.value.to_be_bytes());

    // Compare transaction fields
    actual_tx.from == expected_from
        && actual_tx.to == expected_to
        && actual_tx.value == expected_value
        && actual_tx.input.as_ref() == expected_details.calldata.as_ref()
}

fn verify_events_match_logs(logs: &[Log], expected_events: &[Event]) -> bool {
    // event logs are expected to be ordered by event index
    expected_events.iter().all(|expected_event| {
        usize::try_from(expected_event.event_index)
            .ok()
            .and_then(|idx| logs.get(idx))
            .is_some_and(|log| verify_event_matches_log(log, expected_event))
    })
}

fn verify_event_matches_log(log: &Log, expected_event: &Event) -> bool {
    let expected_contract_address: H160 = expected_event.contract_address.to_array().into();

    log.address == expected_contract_address
        && log.topics.len() == expected_event.topics.len()
        && log
            .topics
            .iter()
            .zip(expected_event.topics.iter())
            .all(|(actual_topic, expected_topic)| actual_topic.as_ref() == expected_topic.as_ref())
        && log.data.as_ref() == expected_event.data.as_ref()
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ampd::types::{EVMAddress, Hash};
    use axelar_wasm_std::fixed_size;
    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelar_wasm_std::voting::Vote;
    use cosmwasm_std::{HexBinary, Uint128, Uint256};
    use ethers_contract::EthEvent;
    use ethers_core::abi::{encode, Token};
    use ethers_core::types::{Bytes, Log, Transaction, TransactionReceipt, H256, U256, U64};
    use event_verifier_api::evm::{Event, EvmEvent, TransactionDetails};
    use evm_gateway::i_axelar_amplifier_gateway::{ContractCallFilter, SignersRotatedFilter};
    use evm_gateway::WeightedSigners;
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ecdsa_test_data};

    use super::{
        verify_event_matches_log, verify_events, verify_events_match_logs, verify_message,
        verify_transaction_details, verify_verifier_set,
    };
    use crate::evm::types::{Message, VerifierSetConfirmation};

    #[test]
    fn should_not_verify_verifier_set_if_tx_id_does_not_match() {
        let (gateway_address, tx_receipt, mut verifier_set) =
            matching_verifier_set_and_tx_receipt();

        verifier_set.message_id.tx_hash = Hash::random().into();
        assert_eq!(
            verify_verifier_set(&gateway_address, &tx_receipt, &verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_tx_failed() {
        let (gateway_address, mut tx_receipt, verifier_set) =
            matching_verifier_set_and_tx_receipt();

        tx_receipt.status = Some(0u64.into());
        assert_eq!(
            verify_verifier_set(&gateway_address, &tx_receipt, &verifier_set),
            Vote::FailedOnChain
        );
    }

    #[test]
    fn should_not_verify_verifier_set_as_failed_if_not_from_gateway() {
        let (gateway_address, mut tx_receipt, verifier_set) =
            matching_verifier_set_and_tx_receipt();

        tx_receipt.status = Some(0u64.into());
        tx_receipt.logs = vec![]; // No gateway events (as on real Ethereum for failed txs)
        assert_eq!(
            verify_verifier_set(&gateway_address, &tx_receipt, &verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_gateway_address_does_not_match() {
        let (_, tx_receipt, verifier_set) = matching_verifier_set_and_tx_receipt();

        let gateway_address = EVMAddress::random();
        assert_eq!(
            verify_verifier_set(&gateway_address, &tx_receipt, &verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_log_index_does_not_match() {
        let (gateway_address, tx_receipt, mut verifier_set) =
            matching_verifier_set_and_tx_receipt();

        verifier_set.message_id.event_index = 0;
        assert_eq!(
            verify_verifier_set(&gateway_address, &tx_receipt, &verifier_set),
            Vote::NotFound
        );
        verifier_set.message_id.event_index = 2;
        assert_eq!(
            verify_verifier_set(&gateway_address, &tx_receipt, &verifier_set),
            Vote::NotFound
        );
        verifier_set.message_id.event_index = 3;
        assert_eq!(
            verify_verifier_set(&gateway_address, &tx_receipt, &verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_log_index_greater_than_u32_max() {
        let (gateway_address, tx_receipt, mut verifier_set) =
            matching_verifier_set_and_tx_receipt();

        verifier_set.message_id.event_index = u32::MAX as u64 + 1;
        assert_eq!(
            verify_verifier_set(&gateway_address, &tx_receipt, &verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_verifier_set_does_not_match() {
        let (gateway_address, tx_receipt, mut verifier_set) =
            matching_verifier_set_and_tx_receipt();

        verifier_set.verifier_set.threshold = Uint128::from(50u64);
        assert_eq!(
            verify_verifier_set(&gateway_address, &tx_receipt, &verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_verify_verifier_set_if_correct() {
        let (gateway_address, tx_receipt, verifier_set) = matching_verifier_set_and_tx_receipt();

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx_receipt, &verifier_set),
            Vote::SucceededOnChain
        );
    }

    #[test]
    fn should_not_verify_msg_if_tx_id_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = matching_msg_and_tx_receipt();

        msg.message_id.tx_hash = Hash::random().into();
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_tx_failed() {
        let (gateway_address, mut tx_receipt, msg) = matching_msg_and_tx_receipt();

        tx_receipt.status = Some(0u64.into());
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::FailedOnChain
        );
    }

    #[test]
    fn should_not_verify_msg_as_failed_if_not_from_gateway() {
        let (gateway_address, mut tx_receipt, msg) = matching_msg_and_tx_receipt();

        tx_receipt.status = Some(0u64.into());
        tx_receipt.logs = vec![]; // No gateway events (as on real Ethereum for failed txs)
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_gateway_address_does_not_match() {
        let (_, tx_receipt, msg) = matching_msg_and_tx_receipt();

        let gateway_address = EVMAddress::random();
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_log_index_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = matching_msg_and_tx_receipt();

        msg.message_id.event_index = 0;
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
        msg.message_id.event_index = 2;
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
        msg.message_id.event_index = 3;
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_log_index_greater_than_u32_max() {
        let (gateway_address, tx_receipt, mut msg) = matching_msg_and_tx_receipt();

        msg.message_id.event_index = u32::MAX as u64 + 1;
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_msg_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = matching_msg_and_tx_receipt();

        msg.source_address = EVMAddress::random();
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_verify_msg_if_correct() {
        let (gateway_address, tx_receipt, msg) = matching_msg_and_tx_receipt();

        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::SucceededOnChain
        );
    }

    #[test]
    fn should_verify_msg_if_chain_uses_different_casing() {
        let (gateway_address, tx_receipt, msg) = msg_and_tx_receipt_with_different_chain_casing();

        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::SucceededOnChain
        );
    }

    fn matching_verifier_set_and_tx_receipt(
    ) -> (EVMAddress, TransactionReceipt, VerifierSetConfirmation) {
        let tx_id = Hash::random();
        let log_index = 1;
        let gateway_address = EVMAddress::random();

        let verifier_set = build_verifier_set(KeyType::Ecdsa, &ecdsa_test_data::signers());

        let verifier_set = VerifierSetConfirmation {
            message_id: HexTxHashAndEventIndex::new(tx_id, log_index as u64),
            verifier_set,
        };

        let weighted_signers = WeightedSigners::try_from(&verifier_set.verifier_set).unwrap();

        let log = Log {
            transaction_hash: Some(tx_id),
            log_index: Some(log_index.into()),
            address: gateway_address,
            topics: vec![
                SignersRotatedFilter::signature(),
                H256::from_low_u64_be(1),
                weighted_signers.hash().into(),
            ],
            data: encode(&[Token::Bytes(weighted_signers.abi_encode())]).into(),
            ..Default::default()
        };

        let tx_receipt = TransactionReceipt {
            transaction_hash: tx_id,
            status: Some(1u64.into()),
            logs: vec![Log::default(), log, Log::default()],
            ..Default::default()
        };

        (gateway_address, tx_receipt, verifier_set)
    }

    fn mock_message(destination_chain: &str) -> Message {
        let tx_id = Hash::random();
        let log_index = 1;

        Message {
            message_id: HexTxHashAndEventIndex::new(tx_id, log_index as u64)
                .to_string()
                .parse()
                .unwrap(),
            source_address: "0xd48e199950589a4336e4dc43bd2c72ba0c0baa86"
                .parse()
                .unwrap(),
            destination_chain: destination_chain.parse().unwrap(),
            destination_address: "0xb9845f9247a85Ee592273a79605f34E8607d7e75".into(),
            payload_hash: "0x9fcef596d62dca8e51b6ba3414901947c0e6821d4483b2f3327ce87c2d4e662e"
                .parse()
                .unwrap(),
        }
    }

    fn mock_tx_receipt(
        destination_chain: &str,
        gateway_address: ethers_core::types::H160,
        msg: &Message,
    ) -> TransactionReceipt {
        let tx_id = msg.message_id.tx_hash.into();
        let log_index = msg.message_id.event_index.into();

        let filter = ContractCallFilter {
            sender: msg.source_address,
            destination_chain: destination_chain.into(),
            destination_contract_address: msg.destination_address.clone(),
            payload_hash: msg.payload_hash.into(),
            payload: ethers_core::types::Bytes::from_str("0x627566666572").unwrap(),
        };

        let data = ethers_core::abi::encode(&[
            Token::String(filter.destination_chain.clone()),
            Token::String(filter.destination_contract_address.clone()),
            Token::Bytes(filter.payload.to_vec()),
        ]);

        let log = Log {
            transaction_hash: Some(tx_id),
            log_index: Some(log_index),
            address: gateway_address,
            topics: vec![
                ContractCallFilter::signature(),
                H256::from(filter.sender),
                filter.payload_hash.into(),
            ],
            data: data.into(),
            ..Default::default()
        };

        TransactionReceipt {
            transaction_hash: tx_id,
            status: Some(1u64.into()),
            logs: vec![Log::default(), log, Log::default()],
            ..Default::default()
        }
    }

    fn matching_msg_and_tx_receipt() -> (EVMAddress, TransactionReceipt, Message) {
        let gateway_address = EVMAddress::random();

        let destination_chain = "ethereum-2";
        let msg = mock_message(destination_chain);
        let tx_receipt = mock_tx_receipt(destination_chain, gateway_address, &msg);

        (gateway_address, tx_receipt, msg)
    }

    fn msg_and_tx_receipt_with_different_chain_casing() -> (EVMAddress, TransactionReceipt, Message)
    {
        let gateway_address = EVMAddress::random();

        let msg = mock_message("ethereum-2");
        let tx_receipt = mock_tx_receipt("Ethereum-2", gateway_address, &msg);

        (gateway_address, tx_receipt, msg)
    }

    // Helper function to create a mock transaction
    fn mock_transaction() -> Transaction {
        Transaction {
            hash: H256::random(),
            nonce: U256::from(1),
            block_hash: Some(H256::random()),
            block_number: Some(U64::from(12345)),
            transaction_index: Some(U64::from(0)),
            from: "0x742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b8"
                .parse()
                .unwrap(),
            to: Some(
                "0x742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b8"
                    .parse()
                    .unwrap(),
            ),
            value: U256::from(1000),
            gas_price: Some(U256::from(20_000_000_000u64)),
            gas: U256::from(21000),
            input: Bytes::from(vec![0x12, 0x34, 0x56, 0x78]),
            v: U64::from(27),
            r: U256::from(1),
            s: U256::from(1),
            transaction_type: None,
            access_list: None,
            max_priority_fee_per_gas: None,
            max_fee_per_gas: None,
            chain_id: None,
            other: ethers_core::types::OtherFields::default(),
        }
    }

    // Helper function to create a mock EvmEvent
    fn mock_evm_event(tx_hash: H256, include_tx_details: bool) -> EvmEvent {
        let tx_details = if include_tx_details {
            Some(TransactionDetails {
                from: cosmwasm_std::HexBinary::from_hex("742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b8")
                    .unwrap()
                    .try_into()
                    .unwrap(),
                to: Some(
                    cosmwasm_std::HexBinary::from_hex("742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b8")
                        .unwrap()
                        .try_into()
                        .unwrap(),
                ),
                value: cosmwasm_std::Uint256::from(1000u64),
                calldata: HexBinary::from(vec![0x12, 0x34, 0x56, 0x78]),
            })
        } else {
            None
        };

        EvmEvent {
            transaction_hash: tx_hash.as_bytes().try_into().unwrap(),
            transaction_details: tx_details,
            events: vec![Event {
                contract_address: cosmwasm_std::HexBinary::from_hex(
                    "742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b8",
                )
                .unwrap()
                .try_into()
                .unwrap(),
                event_index: 0,
                topics: vec![cosmwasm_std::HexBinary::from_hex(
                    "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                )
                .unwrap()
                .try_into()
                .unwrap()],
                data: HexBinary::from(vec![0xab, 0xcd, 0xef]),
            }],
        }
    }

    // Helper function to create a matching transaction receipt
    fn mock_tx_receipt_for_events(tx_hash: H256) -> TransactionReceipt {
        let log = Log {
            address: "0x742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b8"
                .parse()
                .unwrap(),
            topics: vec![
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                    .parse()
                    .unwrap(),
            ],
            data: Bytes::from(vec![0xab, 0xcd, 0xef]),
            block_hash: Some(H256::random()),
            block_number: Some(U64::from(12345)),
            transaction_hash: Some(tx_hash),
            transaction_index: Some(U64::from(0)),
            log_index: Some(U256::from(0)),
            transaction_log_index: Some(U256::from(0)),
            log_type: None,
            removed: Some(false),
        };

        TransactionReceipt {
            transaction_hash: tx_hash,
            transaction_index: U64::from(0),
            block_hash: Some(H256::random()),
            block_number: Some(U64::from(12345)),
            from: "0x742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b8"
                .parse()
                .unwrap(),
            to: Some(
                "0x742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b8"
                    .parse()
                    .unwrap(),
            ),
            cumulative_gas_used: U256::from(21000),
            gas_used: Some(U256::from(21000)),
            contract_address: None,
            logs: vec![log],
            status: Some(U64::from(1)), // Success
            root: None,
            logs_bloom: ethers_core::types::Bloom::default(),
            transaction_type: None,
            effective_gas_price: None,
            other: ethers_core::types::OtherFields::default(),
        }
    }

    #[test]
    fn should_verify_events_when_transaction_details_match() {
        let tx_hash = H256::random();
        let tx = mock_transaction();
        let tx_receipt = mock_tx_receipt_for_events(tx_hash);
        let event_data = mock_evm_event(tx_hash, true);

        let result = verify_events(&tx_receipt, Some(&tx), &event_data);
        assert_eq!(result, Vote::SucceededOnChain);
    }

    #[test]
    fn should_verify_events_when_no_transaction_details_provided() {
        let tx_hash = H256::random();
        let tx_receipt = mock_tx_receipt_for_events(tx_hash);
        let event_data = mock_evm_event(tx_hash, false);

        let result = verify_events(&tx_receipt, None, &event_data);
        assert_eq!(result, Vote::SucceededOnChain);
    }

    #[test]
    fn should_return_failed_on_chain_when_transaction_failed() {
        let tx_hash = H256::random();
        let mut tx_receipt = mock_tx_receipt_for_events(tx_hash);
        tx_receipt.status = Some(U64::from(0)); // Failed transaction
        let event_data = mock_evm_event(tx_hash, false);

        let result = verify_events(&tx_receipt, None, &event_data);
        assert_eq!(result, Vote::FailedOnChain);
    }

    #[test]
    fn should_not_return_failed_on_chain_for_events_when_logs_dont_match() {
        let tx_hash = H256::random();
        let mut tx_receipt = mock_tx_receipt_for_events(tx_hash);
        tx_receipt.status = Some(U64::from(0)); // Failed transaction
        tx_receipt.logs = vec![]; // No logs (as on real Ethereum for failed txs)
        let event_data = mock_evm_event(tx_hash, false);

        let result = verify_events(&tx_receipt, None, &event_data);
        assert_eq!(result, Vote::NotFound);
    }

    #[test]
    fn should_not_verify_events_when_transaction_hash_mismatches() {
        let tx_hash = H256::random();
        let different_tx_hash = H256::random();
        let tx_receipt = mock_tx_receipt_for_events(tx_hash);
        let event_data = mock_evm_event(different_tx_hash, false);

        let result = verify_events(&tx_receipt, None, &event_data);
        assert_eq!(result, Vote::NotFound);
    }

    #[test]
    fn should_not_verify_events_when_transaction_details_mismatch() {
        let tx_hash = H256::random();
        let mut tx = mock_transaction();
        tx.from = "0x742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b0"
            .parse()
            .unwrap(); // Different from address
        let tx_receipt = mock_tx_receipt_for_events(tx_hash);
        let event_data = mock_evm_event(tx_hash, true);

        let result = verify_events(&tx_receipt, Some(&tx), &event_data);
        assert_eq!(result, Vote::NotFound);
    }

    #[test]
    fn should_not_verify_events_when_transaction_details_expected_but_not_provided() {
        let tx_hash = H256::random();
        let tx_receipt = mock_tx_receipt_for_events(tx_hash);
        let event_data = mock_evm_event(tx_hash, true); // Expects transaction details

        let result = verify_events(&tx_receipt, None, &event_data); // But no transaction provided
        assert_eq!(result, Vote::NotFound);
    }

    #[test]
    fn should_not_verify_events_when_event_data_mismatches() {
        let tx_hash = H256::random();
        let tx_receipt = mock_tx_receipt_for_events(tx_hash);
        let mut event_data = mock_evm_event(tx_hash, false);

        // Change the event data to not match
        event_data.events[0].data = HexBinary::from(vec![0x11, 0x22, 0x33]);

        let result = verify_events(&tx_receipt, None, &event_data);
        assert_eq!(result, Vote::NotFound);
    }

    #[test]
    fn should_not_verify_events_when_event_index_is_wrong() {
        let tx_hash = H256::random();
        let tx_receipt = mock_tx_receipt_for_events(tx_hash);
        let mut event_data = mock_evm_event(tx_hash, false);

        // Change the event index to not match
        event_data.events[0].event_index = 1; // Receipt only has event at index 0

        let result = verify_events(&tx_receipt, None, &event_data);
        assert_eq!(result, Vote::NotFound);
    }

    #[test]
    fn should_not_verify_events_when_contract_address_is_wrong() {
        let tx_hash = H256::random();
        let tx_receipt = mock_tx_receipt_for_events(tx_hash);
        let mut event_data = mock_evm_event(tx_hash, false);

        // Change the contract address to not match
        event_data.events[0].contract_address =
            cosmwasm_std::HexBinary::from_hex("742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b0")
                .unwrap()
                .try_into()
                .unwrap();

        let result = verify_events(&tx_receipt, None, &event_data);
        assert_eq!(result, Vote::NotFound);
    }

    #[test]
    fn should_not_verify_events_when_topics_are_wrong() {
        let tx_hash = H256::random();
        let tx_receipt = mock_tx_receipt_for_events(tx_hash);
        let mut event_data = mock_evm_event(tx_hash, false);

        // Change the topics to not match
        event_data.events[0].topics = vec![cosmwasm_std::HexBinary::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap()
        .try_into()
        .unwrap()];

        let result = verify_events(&tx_receipt, None, &event_data);
        assert_eq!(result, Vote::NotFound);
    }

    // Tests for helper functions
    #[test]
    fn should_verify_transaction_details_when_all_fields_match() {
        let tx = mock_transaction();
        let tx_details = TransactionDetails {
            calldata: HexBinary::from(tx.input.to_vec()),
            from: fixed_size::HexBinary::<20>::try_from(tx.from.as_bytes()).unwrap(),
            to: Some(fixed_size::HexBinary::<20>::try_from(tx.to.unwrap().as_bytes()).unwrap()),
            value: tx.value.as_u128().into(),
        };

        assert!(verify_transaction_details(&tx, &tx_details));
    }

    #[test]
    fn should_not_verify_transaction_details_when_from_address_is_wrong() {
        let tx = mock_transaction();
        let tx_details = TransactionDetails {
            calldata: HexBinary::from(tx.input.to_vec()),
            from: cosmwasm_std::HexBinary::from_hex("742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b0")
                .unwrap()
                .try_into()
                .unwrap(), // Different
            to: Some(fixed_size::HexBinary::<20>::try_from(tx.to.unwrap().as_bytes()).unwrap()),
            value: tx.value.as_u128().into(),
        };

        assert!(!verify_transaction_details(&tx, &tx_details));
    }

    #[test]
    fn should_not_verify_transaction_details_when_to_address_is_wrong() {
        let tx = mock_transaction();
        let tx_details = TransactionDetails {
            calldata: HexBinary::from(tx.input.to_vec()),
            from: fixed_size::HexBinary::<20>::try_from(tx.from.as_bytes()).unwrap(),
            to: Some(
                cosmwasm_std::HexBinary::from_hex("742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b0")
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ), // Different
            value: tx.value.as_u128().into(),
        };

        assert!(!verify_transaction_details(&tx, &tx_details));
    }

    #[test]
    fn should_not_verify_transaction_details_when_value_is_wrong() {
        let tx = mock_transaction();
        let tx_details = TransactionDetails {
            calldata: HexBinary::from(vec![0x12, 0x34, 0x56, 0x78]),
            from: fixed_size::HexBinary::<20>::try_from(tx.from.as_bytes()).unwrap(),
            to: Some(fixed_size::HexBinary::<20>::try_from(tx.to.unwrap().as_bytes()).unwrap()),
            value: Uint256::from(999u128), // Different value
        };

        assert!(!verify_transaction_details(&tx, &tx_details));
    }

    #[test]
    fn should_not_verify_transaction_details_when_calldata_is_wrong() {
        let tx = mock_transaction();
        let tx_details = TransactionDetails {
            calldata: HexBinary::from(vec![0x11, 0x22, 0x33, 0x44]), // Different
            from: fixed_size::HexBinary::<20>::try_from(tx.from.as_bytes()).unwrap(),
            to: Some(fixed_size::HexBinary::<20>::try_from(tx.to.unwrap().as_bytes()).unwrap()),
            value: tx.value.as_u128().into(),
        };

        assert!(!verify_transaction_details(&tx, &tx_details));
    }

    #[test]
    fn should_not_verify_transaction_details_when_to_address_is_none_but_actual_has_to() {
        let tx = mock_transaction(); // This has a to address
        let tx_details_to_verify = TransactionDetails {
            from: cosmwasm_std::HexBinary::from_hex("742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b8")
                .unwrap()
                .try_into()
                .unwrap(),
            to: None, // Expected no to address
            value: cosmwasm_std::Uint256::from(1000u64),
            calldata: HexBinary::from(vec![0x12, 0x34, 0x56, 0x78]),
        };

        // Should fail because expected.to is None but actual.to is Some(address)
        assert!(!verify_transaction_details(&tx, &tx_details_to_verify));
    }

    #[test]
    fn should_verify_transaction_details_when_to_address_is_none() {
        let mut tx = mock_transaction();
        tx.to = None; // Contract creation transaction
        let tx_details_to_verify = TransactionDetails {
            from: cosmwasm_std::HexBinary::from_hex("742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b8")
                .unwrap()
                .try_into()
                .unwrap(),
            to: None, // No specific to address expected
            value: cosmwasm_std::Uint256::from(1000u64),
            calldata: HexBinary::from(vec![0x12, 0x34, 0x56, 0x78]),
        };

        assert!(verify_transaction_details(&tx, &tx_details_to_verify));
    }

    #[test]
    fn should_verify_event_matches_log_when_all_fields_match() {
        let log = Log {
            address: "0x742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b9"
                .parse()
                .unwrap(),
            topics: vec![
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                    .parse()
                    .unwrap(),
            ],
            data: Bytes::from(vec![0xab, 0xcd, 0xef]),
            ..Default::default()
        };

        let event = Event {
            contract_address: cosmwasm_std::HexBinary::from_hex(
                "742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b9",
            )
            .unwrap()
            .try_into()
            .unwrap(),
            event_index: 0,
            topics: vec![cosmwasm_std::HexBinary::from_hex(
                "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            )
            .unwrap()
            .try_into()
            .unwrap()],
            data: HexBinary::from(vec![0xab, 0xcd, 0xef]),
        };

        assert!(verify_event_matches_log(&log, &event));
    }

    #[test]
    fn should_not_verify_event_matches_log_when_address_is_wrong() {
        let log = Log {
            address: "0x742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b9"
                .parse()
                .unwrap(),
            topics: vec![
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                    .parse()
                    .unwrap(),
            ],
            data: Bytes::from(vec![0xab, 0xcd, 0xef]),
            ..Default::default()
        };

        let event = Event {
            contract_address: cosmwasm_std::HexBinary::from_hex(
                "742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b0",
            )
            .unwrap()
            .try_into()
            .unwrap(), // Different
            event_index: 0,
            topics: vec![cosmwasm_std::HexBinary::from_hex(
                "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            )
            .unwrap()
            .try_into()
            .unwrap()],
            data: HexBinary::from(vec![0xab, 0xcd, 0xef]),
        };

        assert!(!verify_event_matches_log(&log, &event));
    }

    #[test]
    fn should_not_verify_event_matches_log_when_topics_count_is_wrong() {
        let log = Log {
            address: "0x742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b9"
                .parse()
                .unwrap(),
            topics: vec![
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                    .parse()
                    .unwrap(),
            ],
            data: Bytes::from(vec![0xab, 0xcd, 0xef]),
            ..Default::default()
        };

        let event = Event {
            contract_address: cosmwasm_std::HexBinary::from_hex(
                "742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b9",
            )
            .unwrap()
            .try_into()
            .unwrap(),
            event_index: 0,
            topics: vec![
                cosmwasm_std::HexBinary::from_hex(
                    "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                )
                .unwrap()
                .try_into()
                .unwrap(),
                cosmwasm_std::HexBinary::from_hex(
                    "0000000000000000000000000000000000000000000000000000000000000001",
                )
                .unwrap()
                .try_into()
                .unwrap(), // Extra topic
            ],
            data: HexBinary::from(vec![0xab, 0xcd, 0xef]),
        };

        assert!(!verify_event_matches_log(&log, &event));
    }

    #[test]
    fn should_not_verify_event_matches_log_when_topic_value_is_wrong() {
        let log = Log {
            address: "0x742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b9"
                .parse()
                .unwrap(),
            topics: vec![
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                    .parse()
                    .unwrap(),
            ],
            data: Bytes::from(vec![0xab, 0xcd, 0xef]),
            ..Default::default()
        };

        let event = Event {
            contract_address: cosmwasm_std::HexBinary::from_hex(
                "742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b9",
            )
            .unwrap()
            .try_into()
            .unwrap(),
            event_index: 0,
            topics: vec![
                cosmwasm_std::HexBinary::from_hex(
                    "0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap()
                .try_into()
                .unwrap(), // Different topic
            ],
            data: HexBinary::from(vec![0xab, 0xcd, 0xef]),
        };

        assert!(!verify_event_matches_log(&log, &event));
    }

    #[test]
    fn should_not_verify_event_matches_log_when_data_is_wrong() {
        let log = Log {
            address: "0x742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b9"
                .parse()
                .unwrap(),
            topics: vec![
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                    .parse()
                    .unwrap(),
            ],
            data: Bytes::from(vec![0xab, 0xcd, 0xef]),
            ..Default::default()
        };

        let event = Event {
            contract_address: cosmwasm_std::HexBinary::from_hex(
                "742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b9",
            )
            .unwrap()
            .try_into()
            .unwrap(),
            event_index: 0,
            topics: vec![cosmwasm_std::HexBinary::from_hex(
                "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            )
            .unwrap()
            .try_into()
            .unwrap()],
            data: HexBinary::from(vec![0x11, 0x22, 0x33]), // Different data
        };

        assert!(!verify_event_matches_log(&log, &event));
    }

    #[test]
    fn should_verify_events_match_logs_when_all_events_match() {
        let logs = vec![Log {
            address: "0x742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b9"
                .parse()
                .unwrap(),
            topics: vec![
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                    .parse()
                    .unwrap(),
            ],
            data: Bytes::from(vec![0xab, 0xcd, 0xef]),
            ..Default::default()
        }];

        let events = vec![Event {
            contract_address: cosmwasm_std::HexBinary::from_hex(
                "742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b9",
            )
            .unwrap()
            .try_into()
            .unwrap(),
            event_index: 0,
            topics: vec![cosmwasm_std::HexBinary::from_hex(
                "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            )
            .unwrap()
            .try_into()
            .unwrap()],
            data: HexBinary::from(vec![0xab, 0xcd, 0xef]),
        }];

        assert!(verify_events_match_logs(&logs, &events));
    }

    #[test]
    fn should_not_verify_events_match_logs_when_event_index_is_wrong() {
        let logs = vec![Log {
            address: "0x742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b9"
                .parse()
                .unwrap(),
            topics: vec![
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                    .parse()
                    .unwrap(),
            ],
            data: Bytes::from(vec![0xab, 0xcd, 0xef]),
            ..Default::default()
        }];

        let events = vec![Event {
            contract_address: cosmwasm_std::HexBinary::from_hex(
                "742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b9",
            )
            .unwrap()
            .try_into()
            .unwrap(),
            event_index: 1, // Wrong index - logs only has index 0
            topics: vec![cosmwasm_std::HexBinary::from_hex(
                "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            )
            .unwrap()
            .try_into()
            .unwrap()],
            data: HexBinary::from(vec![0xab, 0xcd, 0xef]),
        }];

        assert!(!verify_events_match_logs(&logs, &events));
    }

    #[test]
    fn should_verify_events_match_logs_with_multiple_events() {
        let logs = vec![
            Log {
                address: "0x742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b9"
                    .parse()
                    .unwrap(),
                topics: vec![
                    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                        .parse()
                        .unwrap(),
                ],
                data: Bytes::from(vec![0xab, 0xcd, 0xef]),
                ..Default::default()
            },
            Log {
                address: "0x742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b0"
                    .parse()
                    .unwrap(),
                topics: vec![
                    "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
                        .parse()
                        .unwrap(),
                ],
                data: Bytes::from(vec![0x12, 0x34, 0x56]),
                ..Default::default()
            },
        ];

        let events = vec![
            Event {
                contract_address: cosmwasm_std::HexBinary::from_hex(
                    "742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b9",
                )
                .unwrap()
                .try_into()
                .unwrap(),
                event_index: 0,
                topics: vec![cosmwasm_std::HexBinary::from_hex(
                    "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                )
                .unwrap()
                .try_into()
                .unwrap()],
                data: HexBinary::from(vec![0xab, 0xcd, 0xef]),
            },
            Event {
                contract_address: cosmwasm_std::HexBinary::from_hex(
                    "742d35Cc6635C0532925a3b8D5C9C8b8b8b8b8b0",
                )
                .unwrap()
                .try_into()
                .unwrap(),
                event_index: 1,
                topics: vec![cosmwasm_std::HexBinary::from_hex(
                    "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
                )
                .unwrap()
                .try_into()
                .unwrap()],
                data: HexBinary::from(vec![0x12, 0x34, 0x56]),
            },
        ];

        assert!(verify_events_match_logs(&logs, &events));
    }

    #[test]
    fn should_not_verify_events_when_events_list_is_empty() {
        let tx_hash = H256::random();
        let tx_receipt = mock_tx_receipt_for_events(tx_hash);
        let event_data = EvmEvent {
            transaction_hash: tx_hash.as_bytes().try_into().unwrap(),
            transaction_details: None,
            events: vec![], // Empty events should not vacuously match
        };

        let result = verify_events(&tx_receipt, None, &event_data);
        assert_eq!(result, Vote::NotFound);
    }

    #[test]
    fn should_not_verify_events_as_failed_when_events_list_is_empty() {
        let tx_hash = H256::random();
        let mut tx_receipt = mock_tx_receipt_for_events(tx_hash);
        tx_receipt.status = Some(U64::from(0)); // Failed transaction
        let event_data = EvmEvent {
            transaction_hash: tx_hash.as_bytes().try_into().unwrap(),
            transaction_details: None,
            events: vec![], // Empty events should not vacuously match
        };

        let result = verify_events(&tx_receipt, None, &event_data);
        assert_eq!(result, Vote::NotFound);
    }
}
