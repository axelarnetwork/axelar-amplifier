use cosmwasm_std::Attribute;
use router_api::{Address, ChainName, CrossChainId};

use crate::primitives::ItsMessage;

pub enum Event {
    ItsMessageReceived {
        cc_id: CrossChainId,
        destination_chain: ChainName,
        message: ItsMessage,
    },
    ItsAddressRegistered {
        chain: ChainName,
        address: Address,
    },
    ItsAddressDeregistered {
        chain: ChainName,
    },
}

impl From<Event> for cosmwasm_std::Event {
    fn from(event: Event) -> Self {
        match event {
            Event::ItsMessageReceived {
                cc_id,
                destination_chain,
                message,
            } => make_its_message_event("its_message_received", cc_id, destination_chain, message),
            Event::ItsAddressRegistered { chain, address } => {
                cosmwasm_std::Event::new("its_address_registered")
                    .add_attribute("chain", chain.to_string())
                    .add_attribute("address", address.to_string())
            }
            Event::ItsAddressDeregistered { chain } => {
                cosmwasm_std::Event::new("its_address_deregistered")
                    .add_attribute("chain", chain.to_string())
            }
        }
    }
}

fn make_its_message_event(
    event_name: &str,
    cc_id: CrossChainId,
    destination_chain: ChainName,
    msg: ItsMessage,
) -> cosmwasm_std::Event {
    let message_type: &'static str = (&msg).into();
    let mut attrs = vec![
        Attribute::new("cc_id", cc_id.to_string()),
        Attribute::new("destination_chain", destination_chain.to_string()),
        Attribute::new("message_type", String::from(message_type)),
    ];

    match msg {
        ItsMessage::InterchainTransfer {
            token_id,
            source_address,
            destination_address,
            amount,
            data,
        } => {
            attrs.extend(vec![
                Attribute::new("token_id", token_id.to_string()),
                Attribute::new("source_address", source_address.to_string()),
                Attribute::new("destination_address", destination_address.to_string()),
                Attribute::new("amount", amount.to_string()),
                Attribute::new("data", data.to_string()),
            ]);
        }
        ItsMessage::DeployInterchainToken {
            token_id,
            name,
            symbol,
            decimals,
            minter,
        } => {
            attrs.extend(vec![
                Attribute::new("token_id", token_id.to_string()),
                Attribute::new("name", name),
                Attribute::new("symbol", symbol),
                Attribute::new("decimals", decimals.to_string()),
                Attribute::new("minter", minter.to_string()),
            ]);
        }
        ItsMessage::DeployTokenManager {
            token_id,
            token_manager_type,
            params,
        } => {
            attrs.extend(vec![
                Attribute::new("token_id", token_id.to_string()),
                Attribute::new("token_manager_type", format!("{:?}", token_manager_type)),
                Attribute::new("params", params.to_string()),
            ]);
        }
    }

    cosmwasm_std::Event::new(event_name).add_attributes(attrs)
}
