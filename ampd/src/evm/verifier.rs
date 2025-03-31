use axelar_wasm_std::voting::Vote;
use ethers_contract::EthLogDecode;
use ethers_core::types::{Log, TransactionReceipt, H256};
use evm_gateway::{IAxelarAmplifierGatewayEvents, WeightedSigners};
use router_api::ChainName;
use tracing::debug;

use crate::handlers::evm_verify_msg::Message;
use crate::handlers::evm_verify_verifier_set::VerifierSetConfirmation;
use crate::types::EVMAddress;

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
    if has_failed(tx_receipt) {
        return Vote::FailedOnChain;
    }

    match event(gateway_address, tx_receipt, expected_event_index) {
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelar_wasm_std::voting::Vote;
    use cosmwasm_std::Uint128;
    use ethers_contract::EthEvent;
    use ethers_core::abi::{encode, Token};
    use ethers_core::types::{Log, TransactionReceipt, H256};
    use evm_gateway::i_axelar_amplifier_gateway::{ContractCallFilter, SignersRotatedFilter};
    use evm_gateway::WeightedSigners;
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ecdsa_test_data};

    use super::{verify_message, verify_verifier_set};
    use crate::handlers::evm_verify_msg::Message;
    use crate::handlers::evm_verify_verifier_set::VerifierSetConfirmation;
    use crate::types::{EVMAddress, Hash};

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
}
