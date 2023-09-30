use ethers::abi::{encode, Token};
use ethers::contract::EthLogDecode;
use ethers::prelude::abigen;
use ethers::types::{Log, TransactionReceipt};

use crate::handlers::evm_verify_msg::Message;
use crate::handlers::evm_verify_worker_set::WorkerSetConfirmation;
use crate::types::EVMAddress;

abigen!(IAxelarGateway, "src/evm/abi/IAxelarGateway.json");

struct IAxelarGatewayEventsWithLog<'a>(&'a Log, IAxelarGatewayEvents);

impl PartialEq<&Message> for IAxelarGatewayEventsWithLog<'_> {
    fn eq(&self, msg: &&Message) -> bool {
        let IAxelarGatewayEventsWithLog(log, event) = self;

        match event {
            IAxelarGatewayEvents::ContractCallFilter(event) => {
                log.transaction_hash == Some(msg.tx_id)
                    && log.log_index == Some(msg.event_index.into())
                    && event.sender == msg.source_address
                    && msg.destination_chain == event.destination_chain
                    && event.destination_contract_address == msg.destination_address
                    && event.payload_hash == msg.payload_hash.as_bytes()
            }
            _ => false,
        }
    }
}

impl PartialEq<&WorkerSetConfirmation> for IAxelarGatewayEventsWithLog<'_> {
    fn eq(&self, worker_set: &&WorkerSetConfirmation) -> bool {
        let IAxelarGatewayEventsWithLog(log, event) = self;

        match event {
            IAxelarGatewayEvents::OperatorshipTransferredFilter(event) => {
                let (operators, weights): (Vec<_>, Vec<_>) = worker_set
                    .operators
                    .weights_by_addresses
                    .iter()
                    .map(|(operator, weight)| {
                        (
                            Token::Address(operator.to_owned()),
                            Token::Uint(weight.as_ref().to_owned()),
                        )
                    })
                    .unzip();

                log.transaction_hash == Some(worker_set.tx_id)
                    && log.log_index == Some(worker_set.event_index.into())
                    && event.new_operators_data
                        == encode(&[
                            Token::Array(operators),
                            Token::Array(weights),
                            Token::Uint(worker_set.operators.threshold.as_ref().to_owned()),
                        ])
            }
            _ => false,
        }
    }
}

fn get_event<'a>(
    gateway_address: &EVMAddress,
    tx_receipt: &'a TransactionReceipt,
    log_index: u64,
) -> Option<IAxelarGatewayEventsWithLog<'a>> {
    tx_receipt
        .logs
        .iter()
        .find(|log| log.log_index == Some(log_index.into()))
        .filter(|log| log.address == *gateway_address)
        .and_then(
            |log| match IAxelarGatewayEvents::decode_log(&log.clone().into()) {
                Ok(event) => Some(IAxelarGatewayEventsWithLog(log, event)),
                Err(_) => None,
            },
        )
}

pub fn verify_message(
    gateway_address: &EVMAddress,
    tx_receipt: &TransactionReceipt,
    msg: &Message,
) -> bool {
    match get_event(gateway_address, tx_receipt, msg.event_index) {
        Some(event) => tx_receipt.transaction_hash == msg.tx_id && event == msg,
        None => false,
    }
}

pub fn verify_worker_set(
    gateway_address: &EVMAddress,
    tx_receipt: &TransactionReceipt,
    worker_set: &WorkerSetConfirmation,
) -> bool {
    match get_event(gateway_address, tx_receipt, worker_set.event_index) {
        Some(event) => tx_receipt.transaction_hash == worker_set.tx_id && event == worker_set,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::evm::verifier::OperatorshipTransferredFilter;
    use crate::handlers::evm_verify_msg::Message;
    use crate::handlers::evm_verify_worker_set::{Operators, WorkerSetConfirmation};
    use cosmwasm_std::Uint256;
    use ethers::abi::{encode, Token};
    use ethers::contract::EthEvent;
    use ethers::types::{Log, TransactionReceipt};

    use super::i_axelar_gateway::ContractCallFilter;
    use super::{verify_message, verify_worker_set};
    use crate::types::{EVMAddress, Hash};

    #[test]
    fn should_not_verify_worker_set_if_tx_id_does_not_match() {
        let (gateway_address, tx_receipt, mut worker_set) =
            get_matching_worker_set_and_tx_receipt();

        worker_set.tx_id = Hash::random();
        assert!(!verify_worker_set(
            &gateway_address,
            &tx_receipt,
            &worker_set
        ));
    }

    #[test]
    fn should_not_verify_worker_set_if_gateway_address_does_not_match() {
        let (_, tx_receipt, worker_set) = get_matching_worker_set_and_tx_receipt();

        let gateway_address = EVMAddress::random();
        assert!(!verify_worker_set(
            &gateway_address,
            &tx_receipt,
            &worker_set
        ));
    }

    #[test]
    fn should_not_verify_worker_set_if_log_index_does_not_match() {
        let (gateway_address, tx_receipt, mut worker_set) =
            get_matching_worker_set_and_tx_receipt();

        worker_set.event_index = 0;
        assert!(!verify_worker_set(
            &gateway_address,
            &tx_receipt,
            &worker_set
        ));
        worker_set.event_index = 2;
        assert!(!verify_worker_set(
            &gateway_address,
            &tx_receipt,
            &worker_set
        ));
        worker_set.event_index = 3;
        assert!(!verify_worker_set(
            &gateway_address,
            &tx_receipt,
            &worker_set
        ));
    }

    #[test]
    fn should_not_verify_worker_set_if_worker_set_does_not_match() {
        let (gateway_address, tx_receipt, mut worker_set) =
            get_matching_worker_set_and_tx_receipt();

        worker_set.operators.threshold = Uint256::from(50u64).into();
        assert!(!verify_worker_set(
            &gateway_address,
            &tx_receipt,
            &worker_set
        ));
    }

    #[test]
    fn should_verify_worker_set_if_correct() {
        let (gateway_address, tx_receipt, worker_set) = get_matching_worker_set_and_tx_receipt();

        assert!(verify_worker_set(
            &gateway_address,
            &tx_receipt,
            &worker_set
        ));
    }

    #[test]
    fn should_not_verify_msg_if_tx_id_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_receipt();

        msg.tx_id = Hash::random();
        assert!(!verify_message(&gateway_address, &tx_receipt, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_gateway_address_does_not_match() {
        let (_, tx_receipt, msg) = get_matching_msg_and_tx_receipt();

        let gateway_address = EVMAddress::random();
        assert!(!verify_message(&gateway_address, &tx_receipt, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_log_index_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_receipt();

        msg.event_index = 0;
        assert!(!verify_message(&gateway_address, &tx_receipt, &msg));
        msg.event_index = 2;
        assert!(!verify_message(&gateway_address, &tx_receipt, &msg));
        msg.event_index = 3;
        assert!(!verify_message(&gateway_address, &tx_receipt, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_msg_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_receipt();

        msg.source_address = EVMAddress::random();
        assert!(!verify_message(&gateway_address, &tx_receipt, &msg));
    }

    #[test]
    fn should_verify_msg_if_correct() {
        let (gateway_address, tx_receipt, msg) = get_matching_msg_and_tx_receipt();

        assert!(verify_message(&gateway_address, &tx_receipt, &msg));
    }

    fn get_matching_worker_set_and_tx_receipt(
    ) -> (EVMAddress, TransactionReceipt, WorkerSetConfirmation) {
        let tx_id = Hash::random();
        let log_index = 999;
        let gateway_address = EVMAddress::random();

        let worker_set = WorkerSetConfirmation {
            tx_id,
            event_index: log_index,
            operators: Operators {
                threshold: Uint256::from(40u64).into(),
                weights_by_addresses: vec![
                    (EVMAddress::random(), Uint256::from(10u64).into()),
                    (EVMAddress::random(), Uint256::from(20u64).into()),
                    (EVMAddress::random(), Uint256::from(30u64).into()),
                ],
            },
        };
        let (operators, weights): (Vec<_>, Vec<_>) = worker_set
            .operators
            .weights_by_addresses
            .iter()
            .map(|(operator, weight)| {
                (
                    Token::Address(operator.to_owned()),
                    Token::Uint(weight.as_ref().to_owned()),
                )
            })
            .unzip();
        let log = Log {
            transaction_hash: Some(tx_id),
            log_index: Some(log_index.into()),
            address: gateway_address,
            topics: vec![OperatorshipTransferredFilter::signature()],
            data: encode(&[Token::Bytes(encode(&[
                Token::Array(operators),
                Token::Array(weights),
                Token::Uint(worker_set.operators.threshold.as_ref().to_owned()),
            ]))])
            .into(),
            ..Default::default()
        };
        let tx_receipt = TransactionReceipt {
            transaction_hash: tx_id,
            logs: vec![Log::default(), log, Log::default()],
            ..Default::default()
        };

        (gateway_address, tx_receipt, worker_set)
    }

    fn get_matching_msg_and_tx_receipt() -> (EVMAddress, TransactionReceipt, Message) {
        let tx_id = Hash::random();
        let log_index = 999;
        let gateway_address = EVMAddress::random();

        let msg = Message {
            tx_id,
            event_index: log_index,
            source_address: "0xd48e199950589a4336e4dc43bd2c72ba0c0baa86"
                .parse()
                .unwrap(),
            destination_chain: "ethereum-2".parse().unwrap(),
            destination_address: "0xb9845f9247a85Ee592273a79605f34E8607d7e75".into(),
            payload_hash: "0x9fcef596d62dca8e51b6ba3414901947c0e6821d4483b2f3327ce87c2d4e662e"
                .parse()
                .unwrap(),
        };
        let log = Log{
            transaction_hash: Some(tx_id),
            log_index: Some(log_index.into()),
            address: gateway_address,
            topics: vec![
                ContractCallFilter::signature(),
                "0x000000000000000000000000d48e199950589a4336e4dc43bd2c72ba0c0baa86".parse().unwrap(),
                "0x9fcef596d62dca8e51b6ba3414901947c0e6821d4483b2f3327ce87c2d4e662e".parse().unwrap(),
            ],
            data : "0x000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000a657468657265756d2d3200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a3078623938343566393234376138354565353932323733613739363035663334453836303764376537350000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000066275666665720000000000000000000000000000000000000000000000000000".parse().unwrap(),
            ..Default::default()
        };
        let tx_receipt = TransactionReceipt {
            transaction_hash: tx_id,
            logs: vec![Log::default(), log, Log::default()],
            ..Default::default()
        };

        (gateway_address, tx_receipt, msg)
    }
}
