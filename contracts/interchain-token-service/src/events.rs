use axelar_wasm_std::{nonempty, IntoEvent};
use interchain_token_service_std::{Message, TokenId};
use router_api::{Address, ChainNameRaw, CrossChainId};

use crate::msg::SupplyModifier;

#[derive(IntoEvent)]
pub enum Event {
    MessageReceived {
        cc_id: CrossChainId,
        destination_chain: ChainNameRaw,
        message: Message,
    },
    TokenMetadataRegistered {
        source_chain: ChainNameRaw,
        token_address: nonempty::HexBinary,
        decimals: u8,
    },
    ItsContractRegistered {
        chain: ChainNameRaw,
        address: Address,
    },
    ItsContractDeregistered {
        chain: ChainNameRaw,
    },
    ExecutionDisabled,
    ExecutionEnabled,
    SupplyModified {
        token_id: TokenId,
        chain: ChainNameRaw,
        supply_modifier: SupplyModifier,
    },
}

#[cfg(test)]
mod test {
    use cosmwasm_std::HexBinary;
    use interchain_token_service_std::{
        DeployInterchainToken, InterchainTransfer, Message, TokenId,
    };
    use router_api::CrossChainId;

    use crate::events::Event;

    #[test]
    fn message_received_with_all_attributes() {
        let test_cases: Vec<Message> = vec![
            InterchainTransfer {
                token_id: TokenId::new([1; 32]),
                source_address: HexBinary::from([1; 32]).try_into().unwrap(),
                destination_address: HexBinary::from([1, 2, 3, 4]).try_into().unwrap(),
                amount: 1u64.try_into().unwrap(),
                data: Some(HexBinary::from([1, 2, 3, 4]).try_into().unwrap()),
            }
            .into(),
            DeployInterchainToken {
                token_id: TokenId::new([1; 32]),
                name: "Test".try_into().unwrap(),
                symbol: "TST".try_into().unwrap(),
                decimals: 18,
                minter: Some(HexBinary::from([1; 32]).try_into().unwrap()),
            }
            .into(),
        ];

        let events: Vec<_> = test_cases
            .into_iter()
            .map(|message| {
                let event = Event::MessageReceived {
                    cc_id: CrossChainId::new("source", "hash").unwrap(),
                    destination_chain: "destination".parse().unwrap(),
                    message,
                };

                cosmwasm_std::Event::from(event)
            })
            .collect();

        goldie::assert_json!(events);
    }

    #[test]
    fn message_received_with_empty_attributes() {
        let test_cases: Vec<Message> = vec![
            InterchainTransfer {
                token_id: TokenId::new([1; 32]),
                source_address: HexBinary::from([1; 32]).try_into().unwrap(),
                destination_address: HexBinary::from([1, 2, 3, 4]).try_into().unwrap(),
                amount: 1u64.try_into().unwrap(),
                data: None,
            }
            .into(),
            InterchainTransfer {
                token_id: TokenId::new([1; 32]),
                source_address: HexBinary::from([0u8]).try_into().unwrap(),
                destination_address: HexBinary::from([0u8]).try_into().unwrap(),
                amount: 1u64.try_into().unwrap(),
                data: None,
            }
            .into(),
            DeployInterchainToken {
                token_id: TokenId::new([1; 32]),
                name: "Test".try_into().unwrap(),
                symbol: "TST".try_into().unwrap(),
                decimals: 18,
                minter: None,
            }
            .into(),
            DeployInterchainToken {
                token_id: TokenId::new([1; 32]),
                name: "t".try_into().unwrap(),
                symbol: "T".try_into().unwrap(),
                decimals: 0,
                minter: None,
            }
            .into(),
        ];

        let events: Vec<_> = test_cases
            .into_iter()
            .map(|message| {
                let event = Event::MessageReceived {
                    cc_id: CrossChainId::new("source", "hash").unwrap(),
                    destination_chain: "destination".parse().unwrap(),
                    message,
                };

                cosmwasm_std::Event::from(event)
            })
            .collect();

        goldie::assert_json!(events);
    }
}
