use cosmwasm_std::{Attribute, Event};
use router_api::{Address, ChainName, CrossChainId};

use crate::primitives::ItsMessage;

pub enum ItsContractEvent {
    ItsMessageReceived {
        cc_id: CrossChainId,
        destination_chain: ChainName,
        message: ItsMessage,
    },
    ItsAddressSet {
        chain: ChainName,
        address: Address,
    },
    ItsAddressRemoved {
        chain: ChainName,
    },
}

impl From<ItsContractEvent> for Event {
    fn from(event: ItsContractEvent) -> Self {
        match event {
            ItsContractEvent::ItsMessageReceived {
                cc_id,
                destination_chain,
                message,
            } => make_its_message_event("its_message_received", cc_id, destination_chain, message),
            ItsContractEvent::ItsAddressSet { chain, address } => Event::new("its_address_set")
                .add_attribute("chain", chain.to_string())
                .add_attribute("address", address.to_string()),
            ItsContractEvent::ItsAddressRemoved { chain } => {
                Event::new("its_address_removed").add_attribute("chain", chain.to_string())
            }
        }
    }
}

fn make_its_message_event(
    event_name: &str,
    cc_id: CrossChainId,
    destination_chain: ChainName,
    msg: ItsMessage,
) -> Event {
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

    Event::new(event_name).add_attributes(attrs)
}
