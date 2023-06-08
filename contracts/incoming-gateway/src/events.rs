use connection_router::events::make_message_event;
use connection_router::state::Message;
use cosmwasm_std::Event;

pub enum GatewayEvent {
    MessageVerified { msg: Message },
    MessageVerificationFailed { msg: Message },
    MessageExecuted { msg: Message },
    MessageExecutionFailed { msg: Message },
}

impl From<GatewayEvent> for Event {
    fn from(other: GatewayEvent) -> Self {
        match other {
            GatewayEvent::MessageVerified { msg } => make_message_event("message_verified", msg),
            GatewayEvent::MessageExecuted { msg } => make_message_event("message_executed", msg),
            GatewayEvent::MessageVerificationFailed { msg } => {
                make_message_event("message_verification_failed", msg)
            }
            GatewayEvent::MessageExecutionFailed { msg } => {
                make_message_event("message_execution_failed", msg)
            }
        }
    }
}
