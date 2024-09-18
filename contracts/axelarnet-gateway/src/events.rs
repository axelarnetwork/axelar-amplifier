use axelar_wasm_std::event::EventExt;
use cosmwasm_std::{Attribute, Coin, Event, HexBinary};
use router_api::Message;

pub enum AxelarnetGatewayEvent {
    ContractCalled {
        msg: Message,
        payload: HexBinary,
        token: Option<Coin>,
    },
    /// Uses the same event name as `GatewayEvent` for consistency
    Routing {
        msg: Message,
    },
    MessageExecuted {
        msg: Message,
    },
}

impl From<AxelarnetGatewayEvent> for Event {
    fn from(other: AxelarnetGatewayEvent) -> Self {
        match other {
            AxelarnetGatewayEvent::ContractCalled {
                msg,
                payload,
                token,
            } => make_message_event("contract_called", msg)
                .add_attribute("payload", payload.to_string())
                .add_attribute_if_some("token", token.map(|token| token.to_string())),
            AxelarnetGatewayEvent::Routing { msg } => make_message_event("routing", msg),
            AxelarnetGatewayEvent::MessageExecuted { msg } => {
                make_message_event("message_executed", msg)
            }
        }
    }
}

fn make_message_event(event_name: &str, msg: Message) -> Event {
    let attrs: Vec<Attribute> = msg.into();

    Event::new(event_name).add_attributes(attrs)
}
