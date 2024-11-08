use cosmwasm_std::{Attribute, Event};
use router_api::Message;
use xrpl_types::msg::XRPLMessage;

pub enum GatewayEvent {
    Verifying { msg: XRPLMessage },
    AlreadyVerified { msg: XRPLMessage },
    AlreadyRejected { msg: XRPLMessage },
    RoutingIncoming { msg: Message },
    UnfitForRouting { msg: Message },
    RoutingOutgoing { msg: Message },
}

fn make_message_event<T: Into<Vec<Attribute>>>(event_name: &str, msg: T) -> Event {
    let attrs: Vec<Attribute> = msg.into();

    Event::new(event_name).add_attributes(attrs)
}

impl From<GatewayEvent> for Event {
    fn from(other: GatewayEvent) -> Self {
        match other {
            GatewayEvent::Verifying { msg } => make_message_event("verifying", msg),
            GatewayEvent::AlreadyVerified { msg } => make_message_event("already_verified", msg),
            GatewayEvent::AlreadyRejected { msg } => make_message_event("already_rejected", msg),
            GatewayEvent::RoutingIncoming { msg } => make_message_event("routing_incoming", msg),
            GatewayEvent::RoutingOutgoing { msg } => make_message_event("routing_outgoing", msg),
            GatewayEvent::UnfitForRouting { msg } => make_message_event("unfit_for_routing", msg),
        }
    }
}
