use connection_router::events::make_message_event_new;
use connection_router::state::NewMessage;
use cosmwasm_std::Event;

pub enum GatewayEvent {
    MessageVerified { msg: NewMessage },
    MessageVerificationFailed { msg: NewMessage },
    MessageRouted { msg: NewMessage },
    MessageRoutingFailed { msg: NewMessage },
}

impl From<GatewayEvent> for Event {
    fn from(other: GatewayEvent) -> Self {
        match other {
            GatewayEvent::MessageVerified { msg } => {
                make_message_event_new("message_verified", msg)
            }
            GatewayEvent::MessageRouted { msg } => make_message_event_new("message_routed", msg),
            GatewayEvent::MessageVerificationFailed { msg } => {
                make_message_event_new("message_verification_failed", msg)
            }
            GatewayEvent::MessageRoutingFailed { msg } => {
                make_message_event_new("message_routing_failed", msg)
            }
        }
    }
}
