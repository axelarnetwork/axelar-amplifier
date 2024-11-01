use interchain_token_service::{HubMessage, Message, TokenId};
use router_api::{Address, ChainNameRaw, CrossChainId};

pub fn dummy_message() -> Message {
    Message::DeployInterchainToken {
        token_id: TokenId::new([2; 32]),
        name: "Test".try_into().unwrap(),
        symbol: "TST".try_into().unwrap(),
        decimals: 18,
        minter: None,
    }
}

pub struct TestMessage {
    pub hub_message: HubMessage,
    pub router_message: router_api::Message,
    pub source_its_chain: ChainNameRaw,
    pub source_its_contract: Address,
    pub destination_its_chain: ChainNameRaw,
    pub destination_its_contract: Address,
}

impl TestMessage {
    pub fn dummy() -> Self {
        let source_its_chain: ChainNameRaw = "source-its-chain".parse().unwrap();
        let source_its_contract: Address = "source-its-contract".parse().unwrap();
        let destination_its_chain: ChainNameRaw = "dest-its-chain".parse().unwrap();
        let destination_its_contract: Address = "dest-its-contract".parse().unwrap();

        let hub_message = HubMessage::SendToHub {
            destination_chain: destination_its_chain.clone(),
            message: dummy_message(),
        };
        let router_message = router_api::Message {
            cc_id: CrossChainId::new(source_its_chain.clone(), "message-id").unwrap(),
            source_address: source_its_contract.clone(),
            destination_chain: "its-hub-chain".parse().unwrap(),
            destination_address: "its-hub-contract".parse().unwrap(),
            payload_hash: [1; 32],
        };

        TestMessage {
            hub_message,
            router_message,
            source_its_chain,
            source_its_contract,
            destination_its_chain,
            destination_its_contract,
        }
    }
}
