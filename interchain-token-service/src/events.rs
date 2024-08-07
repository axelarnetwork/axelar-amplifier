use cosmwasm_std::{Attribute, Event};
use router_api::{Address, ChainName};

use crate::primitives::ItsMessage;

pub enum ItsContractEvent {
    ItsMessageReceived {
        source_chain: ChainName,
        destination_chain: ChainName,
        message: ItsMessage,
    },
    TrustedAddressUpdated {
        chain: ChainName,
        address: Address,
    },
}

impl From<ItsContractEvent> for Event {
    fn from(event: ItsContractEvent) -> Self {
        match event {
            ItsContractEvent::ItsMessageReceived {
                source_chain,
                destination_chain,
                message,
            } => make_its_message_event(
                "its_message_received",
                source_chain,
                destination_chain,
                message,
            ),
            ItsContractEvent::TrustedAddressUpdated { chain, address } => {
                Event::new("trusted_address_updated")
                    .add_attribute("chain", chain.to_string())
                    .add_attribute("address", address.to_string())
            }
        }
    }
}

fn make_its_message_event(
    event_name: &str,
    source_chain: ChainName,
    destination_chain: ChainName,
    msg: ItsMessage,
) -> Event {
    let mut attrs = vec![
        Attribute::new("source_chain", source_chain.to_string()),
        Attribute::new("destination_chain", destination_chain.to_string()),
        Attribute::new("message_type", format!("{:?}", msg)),
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

    Event::new(event_name).add_attributes(attrs)
}
