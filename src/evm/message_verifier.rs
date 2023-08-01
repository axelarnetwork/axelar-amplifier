use ethers::contract::EthLogDecode;
use ethers::prelude::abigen;
use ethers::types::{Log, TransactionReceipt};

use crate::handlers::evm_verify_msg::Message;
use crate::types::EVMAddress;

abigen!(IAxelarGateway, "src/evm/abi/IAxelarGateway.json");

struct IAxelarGatewayEventsWithLog<'a>(&'a Log, IAxelarGatewayEvents);

impl PartialEq<&Message> for IAxelarGatewayEventsWithLog<'_> {
    fn eq(&self, msg: &&Message) -> bool {
        let IAxelarGatewayEventsWithLog(log, event) = self;

        match event {
            IAxelarGatewayEvents::ContractCallFilter(event) => {
                log.transaction_hash == Some(msg.tx_id)
                    && log.transaction_log_index == Some(msg.log_index.into())
                    && event.sender == msg.source_address
                    && event.destination_chain == msg.destination_chain.to_string()
                    && event.destination_contract_address == msg.destination_address
                    && event.payload_hash == msg.payload_hash.as_bytes()
            }
            _ => false,
        }
    }
}

#[allow(dead_code)]
pub fn verify_message(gateway_address: &EVMAddress, tx_receipt: &TransactionReceipt, msg: &Message) -> bool {
    let log = match tx_receipt.logs.get(msg.log_index) {
        Some(log) if log.address == *gateway_address => log,
        _ => return false,
    };
    let event = match IAxelarGatewayEvents::decode_log(&log.clone().into()) {
        Ok(event) => IAxelarGatewayEventsWithLog(log, event),
        Err(_) => return false,
    };

    tx_receipt.transaction_hash == msg.tx_id && event == msg
}

#[cfg(test)]
mod tests {
    use crate::handlers::evm_verify_msg::Message;
    use ethers::contract::EthEvent;
    use ethers::types::{Log, TransactionReceipt};

    use super::i_axelar_gateway::ContractCallFilter;
    use super::verify_message;
    use crate::types::{EVMAddress, Hash};

    #[test]
    fn should_not_verify_if_tx_id_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_receipt();

        msg.tx_id = Hash::random();
        assert!(!verify_message(&gateway_address, &tx_receipt, &msg));
    }

    #[test]
    fn should_not_verify_if_gateway_address_does_not_match() {
        let (_, tx_receipt, msg) = get_matching_msg_and_tx_receipt();

        let gateway_address = EVMAddress::random();
        assert!(!verify_message(&gateway_address, &tx_receipt, &msg));
    }

    #[test]
    fn should_not_verify_if_log_index_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_receipt();

        msg.log_index = 0;
        assert!(!verify_message(&gateway_address, &tx_receipt, &msg));
        msg.log_index = 2;
        assert!(!verify_message(&gateway_address, &tx_receipt, &msg));
        msg.log_index = 3;
        assert!(!verify_message(&gateway_address, &tx_receipt, &msg));
    }

    #[test]
    fn should_not_verify_if_msg_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_receipt();

        msg.source_address = EVMAddress::random();
        assert!(!verify_message(&gateway_address, &tx_receipt, &msg));
    }

    #[test]
    fn should_verify_the_correct_msg() {
        let (gateway_address, tx_receipt, msg) = get_matching_msg_and_tx_receipt();

        assert!(verify_message(&gateway_address, &tx_receipt, &msg));
    }

    fn get_matching_msg_and_tx_receipt() -> (EVMAddress, TransactionReceipt, Message) {
        let tx_id = Hash::random();
        let log_index = 1;
        let gateway_address = EVMAddress::random();

        let msg = Message {
            tx_id,
            log_index,
            source_address: "0xd48e199950589a4336e4dc43bd2c72ba0c0baa86".parse().unwrap(),
            destination_chain: "ethereum-2".parse().unwrap(),
            destination_address: "0xb9845f9247a85Ee592273a79605f34E8607d7e75".into(),
            payload_hash: "0x9fcef596d62dca8e51b6ba3414901947c0e6821d4483b2f3327ce87c2d4e662e"
                .parse()
                .unwrap(),
        };
        let log = Log{
            transaction_hash: Some(tx_id),
            transaction_log_index: Some(log_index.into()),
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
