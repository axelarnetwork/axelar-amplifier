use cosmwasm_std::{Attribute, Event, HexBinary};
use router_api::Message;
use xrpl_types::msg::XRPLMessage;

pub enum XRPLGatewayEvent {
    Verifying { msg: XRPLMessage },
    AlreadyVerified { msg: XRPLMessage },
    AlreadyRejected { msg: XRPLMessage },
    RoutingIncoming { msg: Message },
    UnfitForRouting { msg: Message },
    RoutingOutgoing { msg: Message },
    ContractCalled { msg: Message, payload: HexBinary },
    ExecutionDisabled,
    ExecutionEnabled,
}

fn make_message_event<T: Into<Vec<Attribute>>>(event_name: &str, msg: T) -> Event {
    let attrs: Vec<Attribute> = msg.into();

    Event::new(event_name).add_attributes(attrs)
}

impl From<XRPLGatewayEvent> for Event {
    fn from(other: XRPLGatewayEvent) -> Self {
        match other {
            XRPLGatewayEvent::Verifying { msg } => make_message_event("verifying", msg),
            XRPLGatewayEvent::AlreadyVerified { msg } => {
                make_message_event("already_verified", msg)
            }
            XRPLGatewayEvent::AlreadyRejected { msg } => {
                make_message_event("already_rejected", msg)
            }
            XRPLGatewayEvent::RoutingIncoming { msg } => {
                make_message_event("routing_incoming", msg)
            }
            XRPLGatewayEvent::RoutingOutgoing { msg } => {
                make_message_event("routing_outgoing", msg)
            }
            XRPLGatewayEvent::UnfitForRouting { msg } => {
                make_message_event("unfit_for_routing", msg)
            }
            XRPLGatewayEvent::ContractCalled { msg, payload } => {
                make_message_event("contract_called", msg)
                    .add_attribute("payload", payload.to_string())
            }
            XRPLGatewayEvent::ExecutionDisabled => Event::new("execution_disabled"),
            XRPLGatewayEvent::ExecutionEnabled => Event::new("execution_enabled"),
        }
    }
}
