use ethers::contract::EthLogDecode;
use ethers::prelude::abigen;
use ethers::types::{Log, TransactionReceipt};
use voting_verifier::events::EvmMessage;

use crate::types::{EVMAddress, Hash};

abigen!(IAxelarGateway, "src/evm/abi/IAxelarGateway.json");

struct IAxelarGatewayEventsWithLog<'a>(&'a Log, IAxelarGatewayEvents);

impl PartialEq<&EvmMessage> for IAxelarGatewayEventsWithLog<'_> {
    fn eq(&self, msg: &&EvmMessage) -> bool {
        let IAxelarGatewayEventsWithLog(log, event) = self;
        let msg_transaction_hash: Hash = match msg.tx_id.parse() {
            Ok(hash) => hash,
            Err(_) => return false,
        };
        let msg_source_address: EVMAddress = match msg.source_address.parse() {
            Ok(address) => address,
            Err(_) => return false,
        };

        match event {
            IAxelarGatewayEvents::ContractCallFilter(event) => {
                log.transaction_hash == Some(msg_transaction_hash)
                    && log.transaction_log_index == Some(msg.log_index.into())
                    && event.sender == msg_source_address
                    && event.destination_chain == msg.destination_chain.to_string()
                    && event.destination_contract_address == msg.destination_address
                    && event.payload_hash == msg.payload_hash
            }
            _ => false,
        }
    }
}

#[allow(dead_code)]
pub fn verify_message(gateway_address: &EVMAddress, tx_receipt: &TransactionReceipt, msg: &EvmMessage) -> bool {
    let msg_transaction_hash: Hash = match msg.tx_id.parse() {
        Ok(hash) => hash,
        Err(_) => return false,
    };
    let log = match tx_receipt.logs.get(msg.log_index as usize) {
        Some(log) if log.address == *gateway_address => log,
        _ => return false,
    };
    let event = match IAxelarGatewayEvents::decode_log(&log.clone().into()) {
        Ok(event) => IAxelarGatewayEventsWithLog(log, event),
        Err(_) => return false,
    };

    tx_receipt.transaction_hash == msg_transaction_hash && event == msg
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use cosmwasm_std::HexBinary;
    use ethers::contract::EthEvent;
    use ethers::types::{Bytes, Log, TransactionReceipt};
    use voting_verifier::events::EvmMessage;

    use super::i_axelar_gateway::ContractCallFilter;
    use super::verify_message;
    use crate::types::{EVMAddress, Hash};

    #[test]
    fn should_not_verify_if_tx_id_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_receipt();

        msg.tx_id = format!("0x{:x}", Hash::random());
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

        msg.source_address = format!("0x{:x}", EVMAddress::random());
        assert!(!verify_message(&gateway_address, &tx_receipt, &msg));
    }

    #[test]
    fn should_verify_the_correct_msg() {
        let (gateway_address, tx_receipt, msg) = get_matching_msg_and_tx_receipt();

        assert!(verify_message(&gateway_address, &tx_receipt, &msg));
    }

    fn get_matching_msg_and_tx_receipt() -> (EVMAddress, TransactionReceipt, EvmMessage) {
        let tx_id_hex = "0xb3b73fce56d5df1489dd92c59e1f7491e301cb186f8c0c5e47cdfd187605c1b3";
        let tx_id = Hash::from_str(tx_id_hex).unwrap();
        let log_index = 1;
        let gateway_address = EVMAddress::from_str("0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5").unwrap();

        let msg = EvmMessage {
            tx_id: tx_id_hex.into(),
            log_index,
            source_address: "0xd48e199950589a4336e4dc43bd2c72ba0c0baa86".into(),
            destination_chain: connection_router::types::ChainName::from_str("ethereum-2").unwrap(),
            destination_address: "0xb9845f9247a85Ee592273a79605f34E8607d7e75".into(),
            payload_hash: HexBinary::from_hex("9fcef596d62dca8e51b6ba3414901947c0e6821d4483b2f3327ce87c2d4e662e")
                .unwrap(),
        };
        let log = Log{
            transaction_hash: Some(tx_id),
            transaction_log_index: Some(log_index.into()),
            address: gateway_address,
            topics: vec![
                ContractCallFilter::signature(),
                Hash::from_str("0x000000000000000000000000d48e199950589a4336e4dc43bd2c72ba0c0baa86").unwrap(),
                Hash::from_str("0x9fcef596d62dca8e51b6ba3414901947c0e6821d4483b2f3327ce87c2d4e662e").unwrap(),
            ],
            data : Bytes::from_str("0x000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000a657468657265756d2d3200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a3078623938343566393234376138354565353932323733613739363035663334453836303764376537350000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000066275666665720000000000000000000000000000000000000000000000000000").unwrap(),
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
