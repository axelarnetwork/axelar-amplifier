use cosmwasm_std::{Attribute, Event};
use router_api::Message;

pub enum GatewayEvent {
    Verifying { msg: Message },
    AlreadyVerified { msg: Message },
    AlreadyRejected { msg: Message },
    Routing { msg: Message },
    UnfitForRouting { msg: Message },
}

fn make_message_event(event_name: &str, msg: Message) -> Event {
    let attrs: Vec<Attribute> = msg.into();

    Event::new(event_name).add_attributes(attrs)
}

impl From<GatewayEvent> for Event {
    fn from(other: GatewayEvent) -> Self {
        match other {
            GatewayEvent::Verifying { msg } => make_message_event("verifying", msg),
            GatewayEvent::AlreadyVerified { msg } => make_message_event("already_verified", msg),
            GatewayEvent::AlreadyRejected { msg } => make_message_event("already_rejected", msg),
            GatewayEvent::Routing { msg } => make_message_event("routing", msg),
            GatewayEvent::UnfitForRouting { msg } => make_message_event("unfit_for_routing", msg),
        }
    }
}
