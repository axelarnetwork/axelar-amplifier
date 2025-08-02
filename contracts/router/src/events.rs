use axelar_wasm_std::{IntoEvent, EventAttributes};
use cosmwasm_std::Addr;
use router_api::{ChainName, GatewayDirection, Message};

#[derive(IntoEvent)]
pub enum Event {
    RouterInstantiated {
        admin: Addr,
        governance: Addr,
        axelarnet_gateway: Addr,
        coordinator: Addr,
    },
    ChainRegistered {
        name: ChainName,
        gateway: Addr,
    },
    GatewayInfo {
        chain: ChainName,
        gateway_address: Addr,
    },
    GatewayUpgraded {
        gateway: GatewayInfo,
    },
    ChainFrozen {
        name: ChainName,
        direction: GatewayDirection,
    },
    ChainUnfrozen {
        name: ChainName,
        direction: GatewayDirection,
    },
    MessageRouted(Message),
    RoutingDisabled {},
    RoutingEnabled {},
}

#[derive(serde::Serialize)]
pub struct GatewayInfo {
    pub chain: ChainName,
    pub gateway_address: Addr,
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::MockApi;

    use super::*;
    use crate::events::{Event, GatewayInfo};

    #[test]
    fn router_instantiated_is_serializable() {
        let api = MockApi::default();
        let event = Event::RouterInstantiated {
            admin: api.addr_make("admin"),
            governance: api.addr_make("governance"),
            axelarnet_gateway: api.addr_make("axelarnet_gateway"),
            coordinator: api.addr_make("coordinator"),
        };
        let event = cosmwasm_std::Event::from(event);

        goldie::assert_json!(event);
    }

    #[test]
    fn chain_registered_is_serializable() {
        let api = MockApi::default();
        let event = Event::ChainRegistered {
            name: "ethereum".parse().unwrap(),
            gateway: api.addr_make("gateway"),
        };
        let event = cosmwasm_std::Event::from(event);

        goldie::assert_json!(event);
    }

    #[test]
    fn gateway_info_is_serializable() {
        let api = MockApi::default();
        let event = Event::GatewayInfo {
            chain: "ethereum".parse().unwrap(),
            gateway_address: api.addr_make("gateway"),
        };
        let event = cosmwasm_std::Event::from(event);

        goldie::assert_json!(event);
    }

    #[test]
    fn gateway_upgraded_is_serializable() {
        let api = MockApi::default();
        let event = Event::GatewayUpgraded {
            gateway: GatewayInfo {
                chain: "ethereum".parse().unwrap(),
                gateway_address: api.addr_make("gateway"),
            },
        };
        let event = cosmwasm_std::Event::from(event);

        goldie::assert_json!(event);
    }

    #[test]
    fn chain_frozen_is_serializable() {
        let event = Event::ChainFrozen {
            name: "ethereum".parse().unwrap(),
            direction: GatewayDirection::Bidirectional,
        };
        let event = cosmwasm_std::Event::from(event);

        goldie::assert_json!(event);
    }

    #[test]
    fn chain_unfrozen_is_serializable() {
        let event = Event::ChainUnfrozen {
            name: "ethereum".parse().unwrap(),
            direction: GatewayDirection::Bidirectional,
        };
        let event = cosmwasm_std::Event::from(event);

        goldie::assert_json!(event);
    }

    #[test]
    fn message_routed_is_serializable() {
        let event = Event::MessageRouted(Message {
            cc_id: router_api::CrossChainId::new("ethereum", "some-id").unwrap(),
            source_address: "0x1234".parse().unwrap(),
            destination_chain: "avalanche".parse().unwrap(),
            destination_address: "0x5678".parse().unwrap(),
            payload_hash: [0; 32],
        });
        let event = cosmwasm_std::Event::from(event);

        goldie::assert_json!(event);
    }

    #[test]
    fn message_routed_serializes_like_message() {
        // Create a Message directly
        let message = Message {
            cc_id: router_api::CrossChainId::new("ethereum", "some-id").unwrap(),
            source_address: "0x1234".parse().unwrap(),
            destination_chain: "avalanche".parse().unwrap(),
            destination_address: "0x5678".parse().unwrap(),
            payload_hash: [0; 32],
        };

        // Create MessageRouted event
        let message_routed_event = Event::MessageRouted(message.clone());
        let event = cosmwasm_std::Event::from(message_routed_event);

        // Verify that the event has the correct type
        assert_eq!(event.ty, "message_routed");

        // Verify that all Message fields are present as direct attributes
        let attributes: std::collections::HashMap<_, _> = event
            .attributes
            .iter()
            .map(|attr| (attr.key.as_str(), attr.value.as_str()))
            .collect();

        // Check that cc_id is present and correctly formatted
        assert!(attributes.contains_key("cc_id"));
        let cc_id_value: serde_json::Value = serde_json::from_str(attributes["cc_id"]).unwrap();
        assert_eq!(cc_id_value["message_id"], "some-id");
        assert_eq!(cc_id_value["source_chain"], "ethereum");

        // Check that source_address is present
        assert!(attributes.contains_key("source_address"));
        assert_eq!(attributes["source_address"], "\"0x1234\"");

        // Check that destination_chain is present
        assert!(attributes.contains_key("destination_chain"));
        assert_eq!(attributes["destination_chain"], "\"avalanche\"");

        // Check that destination_address is present
        assert!(attributes.contains_key("destination_address"));
        assert_eq!(attributes["destination_address"], "\"0x5678\"");

        // Check that payload_hash is present and hex-encoded
        assert!(attributes.contains_key("payload_hash"));
        assert_eq!(
            attributes["payload_hash"],
            "\"0000000000000000000000000000000000000000000000000000000000000000\""
        );

        // Verify there's no nested "message" attribute
        assert!(!attributes.contains_key("message"));

        // Verify we have exactly 5 attributes (all Message fields)
        assert_eq!(attributes.len(), 5);
    }

    #[test]
    fn routing_disabled_is_serializable() {
        let event = Event::RoutingDisabled {};
        let event = cosmwasm_std::Event::from(event);

        goldie::assert_json!(event);
    }

    #[test]
    fn routing_enabled_is_serializable() {
        let event = Event::RoutingEnabled {};
        let event = cosmwasm_std::Event::from(event);

        goldie::assert_json!(event);
    }
}
