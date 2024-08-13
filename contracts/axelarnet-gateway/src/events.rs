use cosmwasm_std::{Attribute, Event, HexBinary};
use router_api::Message;

pub enum AxelarnetGatewayEvent {
    ContractCalled {
        msg: Message,
        payload: HexBinary,
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
            AxelarnetGatewayEvent::ContractCalled { msg, payload } => {
                make_message_event("contract_called", msg)
                    .add_attributes(vec![("payload", payload.to_string())])
            }
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
