use cosmwasm_std::{Addr, Event};
use router_api::ChainName;

pub struct ChainsSupportRegistered {
    pub verifier: Addr,
    pub service_name: String,
    pub chains: Vec<ChainName>,
}

pub struct ChainsSupportDeregistered {
    pub verifier: Addr,
    pub service_name: String,
    pub chains: Vec<ChainName>,
}

impl From<ChainsSupportRegistered> for Event {
    fn from(other: ChainsSupportRegistered) -> Self {
        Event::new("chains_support_registered")
            .add_attribute("verifier", other.verifier)
            .add_attribute("service_name", other.service_name)
            .add_attribute(
                "chains",
                serde_json::to_string(&other.chains).expect("failed to serialize chains"),
            )
    }
}

impl From<ChainsSupportDeregistered> for Event {
    fn from(other: ChainsSupportDeregistered) -> Self {
        Event::new("chains_support_deregistered")
            .add_attribute("verifier", other.verifier)
            .add_attribute("service_name", other.service_name)
            .add_attribute(
                "chains",
                serde_json::to_string(&other.chains).expect("failed to serialize chains"),
            )
    }
}
