use cosmwasm_std::{Addr, Attribute, Event};

use crate::{state::Message, types::DomainName};

pub struct RouterInstantiated {
    pub admin: Addr,
}

pub struct DomainRegistered {
    pub name: DomainName,
    pub incoming_gateway: Addr,
    pub outgoing_gateway: Addr,
}

pub enum GatewayDirection {
    Incoming,
    Outgoing,
}

pub struct GatewayInfo {
    pub domain: DomainName,
    pub gateway_address: Addr,
    pub direction: GatewayDirection,
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

impl From<GatewayInfo> for Vec<Attribute> {
    fn from(other: GatewayInfo) -> Self {
        vec![
            ("domain", other.domain.clone()).into(),
            ("gateway_address", other.gateway_address.clone()).into(),
            (
                "gateway_type",
                match &other.direction {
                    GatewayDirection::Incoming => "incoming",
                    GatewayDirection::Outgoing => "outgoing",
                },
            )
                .into(),
        ]
    }
}

impl From<GatewayUpgraded> for Event {
    fn from(other: GatewayUpgraded) -> Self {
        let attrs: Vec<Attribute> = other.gateway.into();
        Event::new("gateway_upgraded").add_attributes(attrs)
    }
}

impl From<GatewayFrozen> for Event {
    fn from(other: GatewayFrozen) -> Self {
        let attrs: Vec<Attribute> = other.gateway.into();
        Event::new("gateway_frozen").add_attributes(attrs)
    }
}

impl From<GatewayUnfrozen> for Event {
    fn from(other: GatewayUnfrozen) -> Self {
        let attrs: Vec<Attribute> = other.gateway.into();
        Event::new("gateway_unfrozen").add_attributes(attrs)
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

impl From<Message> for Vec<Attribute> {
    fn from(other: Message) -> Self {
        vec![
            ("id", other.id()).into(),
            ("source_domain", other.source_domain.clone()).into(),
            ("source_addressess", other.source_address.clone()).into(),
            ("destination_domain", other.destination_domain.clone()).into(),
            ("destination_addressess", other.destination_address.clone()).into(),
            ("payload_hash", other.payload_hash.to_string()).into(),
        ]
    }
}

pub fn make_message_event(event_name: &str, msg: Message) -> Event {
    let attrs: Vec<Attribute> = msg.into();
    Event::new(event_name).add_attributes(attrs)
}

impl From<MessageRouted> for Event {
    fn from(other: MessageRouted) -> Self {
        make_message_event("message_routed", other.msg)
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
                        .iter()
                        .map(|m| m.id())
                        .collect::<Vec<_>>()
                        .join(",")
                ),
            )
    }
}
