use interchain_token_service_std::{DeployInterchainToken, HubMessage, Message, TokenId};
use router_api::{address, chain_name, chain_name_raw, Address, ChainNameRaw, CrossChainId};

pub fn dummy_message() -> Message {
    DeployInterchainToken {
        token_id: TokenId::new([2; 32]),
        name: "Test".try_into().unwrap(),
        symbol: "TST".try_into().unwrap(),
        decimals: 18,
        minter: None,
    }
    .into()
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
        let source_its_chain = chain_name_raw!("source-its-chain");
        let source_its_contract = address!("source-its-contract");
        let destination_its_chain = chain_name_raw!("dest-its-chain");
        let destination_its_contract = address!("dest-its-contract");
        let hub_message = HubMessage::SendToHub {
            destination_chain: destination_its_chain.clone(),
            message: dummy_message(),
        };
        let router_message = router_api::Message {
            cc_id: CrossChainId::new(source_its_chain.clone(), "message-id").unwrap(),
            source_address: source_its_contract.clone(),
            destination_chain: chain_name!("its-hub-chain"),
            destination_address: address!("its-hub-contract"),
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
