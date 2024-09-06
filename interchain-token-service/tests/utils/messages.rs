use cosmwasm_std::{HexBinary, Uint256};
use interchain_token_service::{HubMessage, Message, TokenId};
use router_api::{Address, ChainName, CrossChainId};

pub fn dummy_message() -> Message {
    Message::InterchainTransfer {
        token_id: TokenId::new([2; 32]),
        source_address: HexBinary::from_hex("1234").unwrap(),
        destination_address: HexBinary::from_hex("5678").unwrap(),
        amount: Uint256::from(1000u64),
        data: HexBinary::from_hex("abcd").unwrap(),
    }
}

pub struct TestMessage {
    pub hub_message: HubMessage,
    pub router_message: router_api::Message,
    pub source_its_chain: ChainName,
    pub source_its_address: Address,
    pub destination_its_chain: ChainName,
    pub destination_its_address: Address,
}

impl TestMessage {
    pub fn dummy() -> Self {
        let source_its_chain: ChainName = "source-its-chain".parse().unwrap();
        let source_its_address: Address = "source-its-address".parse().unwrap();
        let destination_its_chain: ChainName = "dest-its-chain".parse().unwrap();
        let destination_its_address: Address = "dest-its-address".parse().unwrap();

        let hub_message = HubMessage::SendToHub {
            destination_chain: destination_its_chain.clone(),
            message: dummy_message(),
        };
        let router_message = router_api::Message {
            cc_id: CrossChainId::new(source_its_chain.clone(), "message-id").unwrap(),
            source_address: source_its_address.clone(),
            destination_chain: "its-hub-chain".parse().unwrap(),
            destination_address: "its-hub-address".parse().unwrap(),
            payload_hash: [1; 32],
        };

        TestMessage {
            hub_message,
            router_message,
            source_its_chain,
            source_its_address,
            destination_its_chain,
            destination_its_address,
        }
    }
}