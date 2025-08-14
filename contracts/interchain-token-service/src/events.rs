use axelar_wasm_std::{nonempty, IntoEvent};
use cosmwasm_std::Uint256;
use interchain_token_service_std::{
    DeployInterchainToken, InterchainTransfer, LinkToken, Message, TokenId,
};
use router_api::{Address, ChainNameRaw, CrossChainId};
use sha3::{Digest, Keccak256};

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
    InterchainTransfer {
        token_id: TokenId,
        source_address: nonempty::HexBinary,
        destination_chain: ChainNameRaw,
        destination_address: nonempty::HexBinary,
        amount: nonempty::Uint256,
        data_hash: Option<[u8; 32]>,
    },
    LinkTokenStarted {
        token_id: TokenId,
        destination_chain: ChainNameRaw,
        token_manager_type: Uint256,
        source_token_address: nonempty::HexBinary,
        destination_token_address: nonempty::HexBinary,
        params: Option<nonempty::HexBinary>,
    },
    InterchainTokenDeploymentStarted {
        token_id: TokenId,
        token_name: nonempty::String,
        token_symbol: nonempty::String,
        token_decimals: u8,
        minter: Option<nonempty::HexBinary>,
        destination_chain: ChainNameRaw,
    },
}

pub fn make_message_event(destination_chain: ChainNameRaw, message: Message) -> Event {
    match message {
        Message::InterchainTransfer(InterchainTransfer {
            token_id,
            source_address,
            destination_address,
            amount,
            data,
        }) => Event::InterchainTransfer {
            token_id,
            source_address,
            destination_chain,
            destination_address,
            amount,
            data_hash: data.map(|data| Keccak256::digest(data.as_ref()).into()),
        },
        Message::LinkToken(LinkToken {
            token_id,
            token_manager_type,
            source_token_address,
            destination_token_address,
            params,
        }) => Event::LinkTokenStarted {
            token_id,
            destination_chain,
            token_manager_type,
            source_token_address,
            destination_token_address,
            params,
        },
        Message::DeployInterchainToken(DeployInterchainToken {
            token_id,
            name,
            symbol,
            decimals,
            minter,
        }) => Event::InterchainTokenDeploymentStarted {
            token_id,
            token_name: name,
            token_symbol: symbol,
            token_decimals: decimals,
            minter,
            destination_chain,
        },
    }
}

#[cfg(test)]
mod test {
    use cosmwasm_std::HexBinary;
    use interchain_token_service_std::{
        DeployInterchainToken, InterchainTransfer, LinkToken, Message, TokenId,
    };
    use router_api::{chain_name_raw, CrossChainId};

    use crate::events::{make_message_event, Event};

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
                    destination_chain: chain_name_raw!("destination"),
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
                    destination_chain: chain_name_raw!("destination"),
                    message,
                };

                cosmwasm_std::Event::from(event)
            })
            .collect();

        goldie::assert_json!(events);
    }

    #[test]
    fn interchain_transfer_events() {
        let destination_chain = chain_name_raw!("ethereum");

        let test_cases = vec![
            // Transfer with data
            InterchainTransfer {
                token_id: TokenId::new([1; 32]),
                source_address: HexBinary::from([1; 32]).try_into().unwrap(),
                destination_address: HexBinary::from([2; 32]).try_into().unwrap(),
                amount: 1000000u64.try_into().unwrap(),
                data: Some(HexBinary::from([1, 2, 3, 4]).try_into().unwrap()),
            },
            // Transfer without data
            InterchainTransfer {
                token_id: TokenId::new([7; 32]),
                source_address: HexBinary::from([0xaa; 20]).try_into().unwrap(),
                destination_address: HexBinary::from([0xbb; 20]).try_into().unwrap(),
                amount: 500000000000000000u64.try_into().unwrap(),
                data: None,
            },
        ];

        let events: Vec<_> = test_cases
            .into_iter()
            .map(|transfer| {
                let event = make_message_event(
                    destination_chain.clone(),
                    Message::InterchainTransfer(transfer),
                );
                cosmwasm_std::Event::from(event)
            })
            .collect();

        goldie::assert_json!(events);
    }

    #[test]
    fn link_token_started_events() {
        let destination_chain = chain_name_raw!("polygon");

        let test_cases = vec![
            // Link token with params
            LinkToken {
                token_id: TokenId::new([1; 32]),
                token_manager_type: 0u64.into(),
                source_token_address: HexBinary::from([0xaa; 20]).try_into().unwrap(),
                destination_token_address: HexBinary::from([0xbb; 20]).try_into().unwrap(),
                params: Some(HexBinary::from([1, 2, 3, 4, 5]).try_into().unwrap()),
            },
            // Link token without params
            LinkToken {
                token_id: TokenId::new([2; 32]),
                token_manager_type: 1u64.into(),
                source_token_address: HexBinary::from([0x11; 32]).try_into().unwrap(),
                destination_token_address: HexBinary::from([0x22; 32]).try_into().unwrap(),
                params: None,
            },
            // Link token with different token manager type
            LinkToken {
                token_id: TokenId::new([0xff; 32]),
                token_manager_type: 2u64.into(),
                source_token_address: HexBinary::from([0x01]).try_into().unwrap(),
                destination_token_address: HexBinary::from([0x02]).try_into().unwrap(),
                params: Some(
                    HexBinary::from([0xde, 0xad, 0xbe, 0xef])
                        .try_into()
                        .unwrap(),
                ),
            },
        ];

        let events: Vec<_> = test_cases
            .into_iter()
            .map(|link_token| {
                let event =
                    make_message_event(destination_chain.clone(), Message::LinkToken(link_token));
                cosmwasm_std::Event::from(event)
            })
            .collect();

        goldie::assert_json!(events);
    }

    #[test]
    fn interchain_token_deployment_started_events() {
        let destination_chain = chain_name_raw!("avalanche");

        let test_cases = vec![
            // Deployment with minter
            DeployInterchainToken {
                token_id: TokenId::new([1; 32]),
                name: "Test Token".try_into().unwrap(),
                symbol: "TEST".try_into().unwrap(),
                decimals: 18,
                minter: Some(HexBinary::from([0xaa; 20]).try_into().unwrap()),
            },
            // Deployment without minter (trustless)
            DeployInterchainToken {
                token_id: TokenId::new([2; 32]),
                name: "Trustless Token".try_into().unwrap(),
                symbol: "TRUST".try_into().unwrap(),
                decimals: 6,
                minter: None,
            },
        ];

        let events: Vec<_> = test_cases
            .into_iter()
            .map(|deploy_token| {
                let event = make_message_event(
                    destination_chain.clone(),
                    Message::DeployInterchainToken(deploy_token),
                );
                cosmwasm_std::Event::from(event)
            })
            .collect();

        goldie::assert_json!(events);
    }

    #[test]
    fn make_message_event_function_coverage() {
        let destination_chain = chain_name_raw!("test-chain");

        // Test all three message types to ensure make_message_event handles them correctly
        let messages = vec![
            Message::InterchainTransfer(InterchainTransfer {
                token_id: TokenId::new([1; 32]),
                source_address: HexBinary::from([0xaa; 20]).try_into().unwrap(),
                destination_address: HexBinary::from([0xbb; 20]).try_into().unwrap(),
                amount: 1000000u64.try_into().unwrap(),
                data: Some(
                    HexBinary::from([0xde, 0xad, 0xbe, 0xef])
                        .try_into()
                        .unwrap(),
                ),
            }),
            Message::InterchainTransfer(InterchainTransfer {
                token_id: TokenId::new([1; 32]),
                source_address: HexBinary::from([0xaa; 20]).try_into().unwrap(),
                destination_address: HexBinary::from([0xbb; 20]).try_into().unwrap(),
                amount: 1000000u64.try_into().unwrap(),
                data: None,
            }),
            Message::LinkToken(LinkToken {
                token_id: TokenId::new([2; 32]),
                token_manager_type: 1u64.into(),
                source_token_address: HexBinary::from([0x11; 32]).try_into().unwrap(),
                destination_token_address: HexBinary::from([0x22; 32]).try_into().unwrap(),
                params: Some(HexBinary::from([1, 2, 3]).try_into().unwrap()),
            }),
            Message::DeployInterchainToken(DeployInterchainToken {
                token_id: TokenId::new([3; 32]),
                name: "Test Function Coverage".try_into().unwrap(),
                symbol: "TFC".try_into().unwrap(),
                decimals: 8,
                minter: None,
            }),
        ];

        let events: Vec<_> = messages
            .into_iter()
            .map(|message| {
                let event = make_message_event(destination_chain.clone(), message);
                cosmwasm_std::Event::from(event)
            })
            .collect();

        goldie::assert_json!(events);
    }
}
