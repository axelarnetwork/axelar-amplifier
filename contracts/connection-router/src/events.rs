use crate::state::{DomainName, Message};
use cosmwasm_std::{Addr, Attribute, Event};

pub struct RouterInstantiated {
    pub admin: Addr,
}

pub struct DomainRegistered {
    pub name: DomainName,
    pub incoming_gateway: Addr,
    pub outgoing_gateway: Addr,
}

pub struct GatewayInfo {
    pub domain: DomainName,
    pub gateway_address: Addr,
    pub incoming: bool, // true if this gateway is an incoming gateway
}

pub struct GatewayUpgraded {
    pub gateway: GatewayInfo,
}

pub struct GatewayFrozen {
    pub gateway: GatewayInfo,
}

pub struct GatewayUnfrozen {
    pub gateway: GatewayInfo,
}

pub struct DomainFrozen {
    pub name: DomainName,
}

pub struct DomainUnfrozen {
    pub name: DomainName,
}

pub struct MessageRouted {
    pub msg: Message,
}

pub struct MessagesConsumed<'a> {
    pub domain: DomainName,
    pub msgs: &'a Vec<Message>,
}

impl From<RouterInstantiated> for Event {
    fn from(other: RouterInstantiated) -> Self {
        Event::new("router_instantiated").add_attribute("admin_address", other.admin)
    }
}

impl From<DomainRegistered> for Event {
    fn from(other: DomainRegistered) -> Self {
        Event::new("domain_registered")
            .add_attribute("name", other.name)
            .add_attribute("incoming_gateway", other.incoming_gateway)
            .add_attribute("outgoing_gateway", other.outgoing_gateway)
    }
}

impl GatewayInfo {
    fn event_attributes(&self) -> Vec<Attribute> {
        vec![
            ("domain", self.domain.clone()).into(),
            ("gateway_address", self.gateway_address.clone()).into(),
            (
                "gateway_type",
                if self.incoming {
                    "incoming"
                } else {
                    "outgoing"
                },
            )
                .into(),
        ]
    }
}

impl From<GatewayUpgraded> for Event {
    fn from(other: GatewayUpgraded) -> Self {
        Event::new("gateway_upgraded").add_attributes(other.gateway.event_attributes())
    }
}

impl From<GatewayFrozen> for Event {
    fn from(other: GatewayFrozen) -> Self {
        Event::new("gateway_frozen").add_attributes(other.gateway.event_attributes())
    }
}

impl From<GatewayUnfrozen> for Event {
    fn from(other: GatewayUnfrozen) -> Self {
        Event::new("gateway_unfrozen").add_attributes(other.gateway.event_attributes())
    }
}

impl From<DomainFrozen> for Event {
    fn from(other: DomainFrozen) -> Self {
        Event::new("domain_frozen").add_attribute("name", other.name)
    }
}

impl From<DomainUnfrozen> for Event {
    fn from(other: DomainUnfrozen) -> Self {
        Event::new("domain_unfrozen").add_attribute("name", other.name)
    }
}

impl Message {
    fn event_attributes(&self) -> Vec<Attribute> {
        vec![
            ("id", self.id()).into(),
            ("source_domain", self.source_domain.clone()).into(),
            ("source_addressess", self.source_address.clone()).into(),
            ("destination_domain", self.destination_domain.clone()).into(),
            ("destination_addressess", self.destination_address.clone()).into(),
            ("payload_hash", self.payload_hash.to_string()).into(),
        ]
    }
}

impl From<MessageRouted> for Event {
    fn from(other: MessageRouted) -> Self {
        let msg = other.msg;
        Event::new("message_routed").add_attributes(msg.event_attributes())
    }
}

impl<'a> From<MessagesConsumed<'a>> for Event {
    fn from(other: MessagesConsumed) -> Self {
        Event::new("messages_consumed")
            .add_attribute("domain", other.domain)
            .add_attribute("count", other.msgs.len().to_string())
            .add_attribute(
                "message_id",
                format!(
                    "[{}]",
                    other
                        .msgs
                        .into_iter()
                        .map(|m| m.id())
                        .collect::<Vec<String>>()
                        .join(",")
                ),
            )
    }
}
