use axelar_wasm_std::event::EventExt;
use router_api::{Address, ChainNameRaw, CrossChainId};

use crate::primitives::Message;
use crate::{DeployInterchainToken, InterchainTransfer, LinkToken, RegisterTokenMetadata};

pub enum Event {
    MessageReceived {
        cc_id: CrossChainId,
        destination_chain: ChainNameRaw,
        message: Message,
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
}

impl From<Event> for cosmwasm_std::Event {
    fn from(event: Event) -> Self {
        match event {
            Event::MessageReceived {
                cc_id,
                destination_chain,
                message,
            } => make_message_event("message_received", cc_id, destination_chain, message),
            Event::ItsContractRegistered { chain, address } => {
                cosmwasm_std::Event::new("its_contract_registered")
                    .add_attribute("chain", chain.to_string())
                    .add_attribute("address", address.to_string())
            }
            Event::ItsContractDeregistered { chain } => {
                cosmwasm_std::Event::new("its_contract_deregistered")
                    .add_attribute("chain", chain.to_string())
            }
            Event::ExecutionDisabled => cosmwasm_std::Event::new("execution_disabled"),
            Event::ExecutionEnabled => cosmwasm_std::Event::new("execution_enabled"),
        }
    }
}

fn make_message_event(
    event_name: &str,
    cc_id: CrossChainId,
    destination_chain: ChainNameRaw,
    msg: Message,
) -> cosmwasm_std::Event {
    let event = cosmwasm_std::Event::new(event_name)
        .add_attribute("cc_id", cc_id.to_string())
        .add_attribute("destination_chain", destination_chain.to_string())
        .add_attribute("message_type", msg.as_ref().to_string());

    match msg {
        Message::InterchainTransfer(InterchainTransfer {
            token_id,
            source_address,
            destination_address,
            amount,
            data,
        }) => event
            .add_attribute("token_id", token_id.to_string())
            .add_attribute("source_address", source_address.to_string())
            .add_attribute("destination_address", destination_address.to_string())
            .add_attribute("amount", amount.to_string())
            .add_attribute_if_some("data", data.map(|data| data.to_string())),
        Message::DeployInterchainToken(DeployInterchainToken {
            token_id,
            name,
            symbol,
            decimals,
            minter,
        }) => event
            .add_attribute("token_id", token_id.to_string())
            .add_attribute("name", name)
            .add_attribute("symbol", symbol)
            .add_attribute("decimals", decimals.to_string())
            .add_attribute_if_some("minter", minter.map(|minter| minter.to_string())),
        Message::RegisterToken(RegisterTokenMetadata { address, decimals }) => event
            .add_attribute("decimals", decimals.to_string())
            .add_attribute("address", address.to_string()),
        Message::LinkToken(LinkToken {
            token_id,
            token_manager_type,
            source_token_address,
            destination_token_address,
            params,
        }) => event
            .add_attribute("token_id", token_id.to_string())
            .add_attribute("token_manager_type", token_manager_type.to_string())
            .add_attribute("source_token_address", source_token_address.to_string())
            .add_attribute(
                "destination_token_address",
                destination_token_address.to_string(),
            )
            .add_attribute_if_some("params", params.map(|params| params.to_string())),
    }
}

#[cfg(test)]
mod test {
    use cosmwasm_std::HexBinary;
    use router_api::CrossChainId;

    use crate::events::Event;
    use crate::{DeployInterchainToken, InterchainTransfer, Message, TokenId};

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
