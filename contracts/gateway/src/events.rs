use connection_router::events::make_message_event;
use connection_router::state::Message;
use cosmwasm_std::Event;

pub enum GatewayEvent {
    MessageVerified { msg: Message },
    MessageVerificationFailed { msg: Message },
    MessageRouted { msg: Message },
    MessageRoutingFailed { msg: Message },
}

impl From<GatewayEvent> for Event {
    fn from(other: GatewayEvent) -> Self {
        match other {
            GatewayEvent::MessageVerified { msg } => make_message_event("message_verified", msg),
            GatewayEvent::MessageRouted { msg } => make_message_event("message_routed", msg),
            GatewayEvent::MessageVerificationFailed { msg } => {
                make_message_event("message_verification_failed", msg)
            }
            GatewayEvent::MessageRoutingFailed { msg } => {
                make_message_event("message_routing_failed", msg)
            }
        }
    }
}
