use axelar_wasm_std::IntoEvent;
use cosmwasm_std::Addr;
use router_api::ChainName;

#[derive(IntoEvent)]
pub enum Event {
    ChainsSupportRegistered {
        verifier: Addr,
        service_name: String,
        chains: Vec<ChainName>,
    },
    ChainsSupportDeregistered {
        verifier: Addr,
        service_name: String,
        chains: Vec<ChainName>,
    },
}

#[cfg(test)]
mod test {
    use cosmwasm_std::{Addr, Event as CosmwasmEvent};

    use super::Event;

    #[test]
    fn chains_support_registered_is_serializable() {
        let event = Event::ChainsSupportRegistered {
            verifier: Addr::unchecked("verifier"),
            service_name: "test_service".to_string(),
            chains: vec!["ethereum".parse().unwrap(), "polygon".parse().unwrap()],
        };
        let cosmwasm_event: CosmwasmEvent = event.into();
        goldie::assert_json!(cosmwasm_event);
    }

    #[test]
    fn chains_support_deregistered_is_serializable() {
        let event = Event::ChainsSupportDeregistered {
            verifier: Addr::unchecked("verifier"),
            service_name: "test_service".to_string(),
            chains: vec!["ethereum".parse().unwrap(), "polygon".parse().unwrap()],
        };
        let cosmwasm_event: CosmwasmEvent = event.into();
        goldie::assert_json!(cosmwasm_event);
    }
}
