use connection_router::events::make_message_event;
use connection_router::state::Message;
use cosmwasm_std::Event;

pub enum GatewayEvent {
    Verifying { msg: Message },
    AlreadyVerified { msg: Message },
    Routing { msg: Message },
    UnfitForRouting { msg: Message },
}

impl From<GatewayEvent> for Event {
    fn from(other: GatewayEvent) -> Self {
        match other {
            GatewayEvent::Verifying { msg } => make_message_event("verifying", msg),
            GatewayEvent::Routing { msg } => make_message_event("routing", msg),
            GatewayEvent::AlreadyVerified { msg } => make_message_event("already_verified", msg),
            GatewayEvent::UnfitForRouting { msg } => make_message_event("unfit_for_routing", msg),
        }
    }
}
