use axelar_wasm_std::event;
use cosmwasm_std::{Addr, Attribute, Event};
use router_api::{ChainName, GatewayDirection, Message};

pub struct RouterInstantiated {
    pub admin: Addr,
    pub governance: Addr,
    pub nexus_gateway: Addr,
}

pub struct ChainRegistered {
    pub name: ChainName,
    pub gateway: Addr,
}

pub struct GatewayInfo {
    pub chain: ChainName,
    pub gateway_address: Addr,
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

pub struct ChainFrozen {
    pub name: ChainName,
    pub direction: GatewayDirection,
}

pub struct ChainUnfrozen {
    pub name: ChainName,
    pub direction: GatewayDirection,
}

pub struct MessageRouted {
    pub msg: Message,
}

impl From<RouterInstantiated> for Event {
    fn from(other: RouterInstantiated) -> Self {
        Event::new("router_instantiated")
            .add_attribute("admin_address", other.admin)
            .add_attribute("governance_address", other.governance)
    }
}

impl From<ChainRegistered> for Event {
    fn from(other: ChainRegistered) -> Self {
        Event::new("chain_registered")
            .add_attribute("name", other.name)
            .add_attribute("gateway", other.gateway)
    }
}

impl From<GatewayInfo> for Vec<Attribute> {
    fn from(other: GatewayInfo) -> Self {
        vec![
            ("chain", other.chain.clone()).into(),
            ("gateway_address", other.gateway_address).into(),
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

impl From<ChainFrozen> for Event {
    fn from(other: ChainFrozen) -> Self {
        Event::new("chain_frozen")
            .add_attribute("name", other.name)
            .add_attribute(
                "direction",
                event::attribute_value(&other.direction).expect("failed to serialize direction"),
            )
    }
}

impl From<ChainUnfrozen> for Event {
    fn from(other: ChainUnfrozen) -> Self {
        Event::new("chain_unfrozen")
            .add_attribute("name", other.name)
            .add_attribute(
                "direction",
                event::attribute_value(&other.direction).expect("failed to serialize direction"),
            )
    }
}

impl From<MessageRouted> for Event {
    fn from(other: MessageRouted) -> Self {
        let attrs: Vec<Attribute> = other.msg.into();

        Event::new("message_routed").add_attributes(attrs)
    }
}
