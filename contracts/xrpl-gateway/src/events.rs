use axelar_wasm_std::nonempty;
use cosmwasm_std::{Attribute, Event, HexBinary, Uint256};
use interchain_token_service_std::TokenId;
use router_api::{ChainNameRaw, Message};
use xrpl_types::msg::XRPLMessage;
use xrpl_types::types::{XRPLAccountId, XRPLToken, XRPLTokenOrXrp};

pub enum XRPLGatewayEvent {
    Verifying {
        msg: XRPLMessage,
    },
    AlreadyVerified {
        msg: XRPLMessage,
    },
    AlreadyRejected {
        msg: XRPLMessage,
    },
    RoutingIncoming {
        msg: Message,
    },
    UnfitForRouting {
        msg: Message,
    },
    RoutingOutgoing {
        msg: Message,
    },
    ContractCalled {
        msg: Message,
        payload: HexBinary,
    },
    ExecutionDisabled,
    ExecutionEnabled,
    InterchainTransfer {
        token_id: TokenId,
        source_address: XRPLAccountId,
        destination_chain: ChainNameRaw,
        destination_address: nonempty::HexBinary,
        amount: nonempty::Uint256,
        data_hash: Option<[u8; 32]>,
    },
    TokenMetadataRegistered {
        decimals: u8,
        token_address: nonempty::HexBinary,
    },
    LinkTokenStarted {
        token_id: TokenId,
        destination_chain: ChainNameRaw,
        token_manager_type: Uint256,
        source_token_address: nonempty::HexBinary,
        destination_token_address: nonempty::HexBinary,
        params: Option<nonempty::HexBinary>,
    },
    InterchainTokenDeploymentStarted {
        token_id: TokenId,
        token_name: nonempty::String,
        token_symbol: nonempty::String,
        token_decimals: u8,
        minter: Option<nonempty::HexBinary>,
        destination_chain: ChainNameRaw,
    },
    LocalTokenRegistered {
        token_id: TokenId,
        token: XRPLTokenOrXrp,
    },
    RemoteTokenRegistered {
        token_id: TokenId,
        token: XRPLToken,
    },
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
            XRPLGatewayEvent::InterchainTransfer {
                token_id,
                source_address,
                destination_chain,
                destination_address,
                amount,
                data_hash,
            } => {
                let mut event = Event::new("interchain_transfer")
                    .add_attribute("token_id", token_id.to_string())
                    .add_attribute("source_address", source_address.to_string())
                    .add_attribute("destination_chain", destination_chain.to_string())
                    .add_attribute("destination_address", destination_address.to_string())
                    .add_attribute("amount", amount.to_string());

                if let Some(data_hash) = data_hash {
                    event = event.add_attribute("data_hash", HexBinary::from(data_hash).to_string())
                }

                event
            }
            XRPLGatewayEvent::TokenMetadataRegistered {
                decimals,
                token_address,
            } => Event::new("token_metadata_registered")
                .add_attribute("decimals", decimals.to_string())
                .add_attribute("token_address", token_address.to_string()),
            XRPLGatewayEvent::LinkTokenStarted {
                token_id,
                destination_chain,
                token_manager_type,
                source_token_address,
                destination_token_address,
                params,
            } => {
                let mut event = Event::new("link_token_started")
                    .add_attribute("token_id", token_id.to_string())
                    .add_attribute("destination_chain", destination_chain.to_string())
                    .add_attribute("token_manager_type", token_manager_type.to_string())
                    .add_attribute("source_token_address", source_token_address.to_string())
                    .add_attribute(
                        "destination_token_address",
                        destination_token_address.to_string(),
                    );

                if let Some(params) = params {
                    event = event.add_attribute("params", params.to_string());
                }

                event
            }
            XRPLGatewayEvent::InterchainTokenDeploymentStarted {
                token_id,
                token_name,
                token_symbol,
                token_decimals,
                minter,
                destination_chain,
            } => {
                let mut event = Event::new("interchain_token_deployment_started")
                    .add_attribute("token_id", token_id.to_string())
                    .add_attribute("token_name", token_name.to_string())
                    .add_attribute("token_symbol", token_symbol.to_string())
                    .add_attribute("token_decimals", token_decimals.to_string())
                    .add_attribute("destination_chain", destination_chain.to_string());

                if let Some(minter) = minter {
                    event = event.add_attribute("minter", minter.to_string());
                }

                event
            }
            XRPLGatewayEvent::LocalTokenRegistered { token_id, token } => {
                Event::new("local_token_registered")
                    .add_attribute("token_id", token_id.to_string())
                    .add_attribute("token", token.to_string())
            }
            XRPLGatewayEvent::RemoteTokenRegistered { token_id, token } => {
                Event::new("remote_token_registered")
                    .add_attribute("token_id", token_id.to_string())
                    .add_attribute("token", token.to_string())
            }
        }
    }
}
