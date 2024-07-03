use std::collections::HashMap;
use std::vec;

use axelar_wasm_std::msg_id::{self, MessageIdFormat};
use cosmwasm_std::{to_json_binary, Addr, DepsMut, Response, StdResult, Storage, WasmMsg};
use error_stack::{report, ResultExt};
use itertools::Itertools;

use crate::events::{
    ChainFrozen, ChainRegistered, ChainUnfrozen, GatewayInfo, GatewayUpgraded, MessageRouted,
};
use crate::state::{chain_endpoints, Config, State, Store, CONFIG, STATE};
use crate::{events, state};
use axelar_wasm_std::flagset::FlagSet;
use axelar_wasm_std::msg_id::{self, MessageIdFormat};
use router_api::error::Error;
use router_api::{ChainEndpoint, ChainName, Gateway, GatewayDirection, Message};

use crate::events::{
    ChainFrozen, ChainRegistered, ChainUnfrozen, GatewayInfo, GatewayUpgraded, MessageRouted,
};
use crate::state;
use crate::state::{chain_endpoints, Config};

pub fn register_chain(
    deps: DepsMut,
    name: ChainName,
    gateway: Addr,
    msg_id_format: MessageIdFormat,
) -> Result<Response, Error> {
    if find_chain_for_gateway(&deps, &gateway)?.is_some() {
        return Err(Error::GatewayAlreadyRegistered);
    }
    chain_endpoints().update(deps.storage, name.clone(), |chain| match chain {
        Some(_) => Err(Error::ChainAlreadyExists),
        None => Ok(ChainEndpoint {
            name: name.clone(),
            gateway: Gateway {
                address: gateway.clone(),
            },
            frozen_status: FlagSet::from(GatewayDirection::None),
            msg_id_format,
        }),
    })?;
    Ok(Response::new().add_event(ChainRegistered { name, gateway }.into()))
}

pub fn find_chain_for_gateway(
    deps: &DepsMut,
    contract_address: &Addr,
) -> StdResult<Option<ChainEndpoint>> {
    #[allow(deprecated)]
    chain_endpoints()
        .idx
        .gateway
        .find_chain(deps, contract_address)
}

pub fn upgrade_gateway(
    deps: DepsMut,
    chain: ChainName,
    contract_address: Addr,
) -> Result<Response, Error> {
    if find_chain_for_gateway(&deps, &contract_address)?.is_some() {
        return Err(Error::GatewayAlreadyRegistered);
    }
    chain_endpoints().update(deps.storage, chain.clone(), |chain| match chain {
        None => Err(Error::ChainNotFound),
        Some(mut chain) => {
            chain.gateway.address = contract_address.clone();
            Ok(chain)
        }
    })?;
    Ok(Response::new().add_event(
        GatewayUpgraded {
            gateway: GatewayInfo {
                chain,
                gateway_address: contract_address,
            },
        }
        .into(),
    ))
}

fn freeze_specific_chain(
    storage: &mut dyn Storage,
    chain: ChainName,
    direction: GatewayDirection,
) -> Result<ChainFrozen, Error> {
    chain_endpoints().update(storage, chain.clone(), |chain| match chain {
        None => Err(Error::ChainNotFound),
        Some(mut chain) => {
            *chain.frozen_status |= direction;
            Ok(chain)
        }
    })?;

    Ok(ChainFrozen {
        name: chain,
        direction,
    })
}

pub fn freeze_chains(
    deps: DepsMut,
    chains: HashMap<ChainName, GatewayDirection>,
) -> Result<Response, Error> {
    let events: Vec<_> = chains
        .into_iter()
        .map(|(chain, direction)| freeze_specific_chain(deps.storage, chain, direction))
        .map_ok(Event::from)
        .try_collect()?;

    Ok(Response::new().add_events(events))
}

#[allow(clippy::arithmetic_side_effects)] // flagset operations don't cause under/overflows
fn unfreeze_specific_chain(
    storage: &mut dyn Storage,
    chain: ChainName,
    direction: GatewayDirection,
) -> Result<ChainUnfrozen, Error> {
    chain_endpoints().update(storage, chain.clone(), |chain| match chain {
        None => Err(Error::ChainNotFound),
        Some(mut chain) => {
            *chain.frozen_status -= direction;
            Ok(chain)
        }
    })?;

    Ok(ChainUnfrozen {
        name: chain,
        direction,
    })
}

pub fn unfreeze_chains(
    deps: DepsMut,
    chains: HashMap<ChainName, GatewayDirection>,
) -> Result<Response, Error> {
    let events: Vec<_> = chains
        .into_iter()
        .map(|(chain, direction)| unfreeze_specific_chain(deps.storage, chain, direction))
        .map_ok(Event::from)
        .try_collect()?;

    Ok(Response::new().add_events(events))
}

#[derive(thiserror::Error, Debug)]
enum StateUpdateError {
    #[error("router is already in the same state")]
    SameState,
    #[error(transparent)]
    Std(#[from] StdError),
}

pub fn disable_routing(deps: DepsMut) -> Result<Response, Error> {
    let state = STATE.update(deps.storage, |state| match state {
        State::Enabled => Ok(State::Disabled),
        State::Disabled => Err(StateUpdateError::SameState),
    });

    state_toggle_response(state, events::RoutingDisabled)
}

pub fn enable_routing(deps: DepsMut) -> Result<Response, Error> {
    let state = STATE.update(deps.storage, |state| match state {
        State::Disabled => Ok(State::Enabled),
        State::Enabled => Err(StateUpdateError::SameState),
    });

    state_toggle_response(state, events::RoutingEnabled)
}

fn state_toggle_response(
    state: Result<State, StateUpdateError>,
    event: impl Into<Event>,
) -> Result<Response, Error> {
    match state {
        Ok(_) => Ok(Response::new().add_event(event.into())),
        Err(StateUpdateError::SameState) => Ok(Response::new()),
        Err(StateUpdateError::Std(err)) => Err(err.into()),
    }
}

fn verify_msg_ids(
    msgs: &[Message],
    expected_format: &MessageIdFormat,
) -> Result<(), error_stack::Report<Error>> {
    msgs.iter()
        .try_for_each(|msg| msg_id::verify_msg_id(&msg.cc_id.id, expected_format))
        .change_context(Error::InvalidMessageId)
}

fn validate_msgs(
    storage: &dyn Storage,
    config: Config,
    sender: &Addr,
    msgs: Vec<Message>,
) -> error_stack::Result<Vec<Message>, Error> {
    // If sender is the nexus gateway, we cannot validate the source chain
    // because the source chain is registered in the core nexus module.
    // All messages received from the nexus gateway must adhere to the
    // HexTxHashAndEventIndex message ID format.
    if sender == config.nexus_gateway {
        verify_msg_ids(&msgs, &MessageIdFormat::HexTxHashAndEventIndex)?;
        return Ok(msgs);
    }

    let source_chain = state::load_chain_by_gateway(storage, sender)?;
    if source_chain.incoming_frozen() {
        return Err(report!(Error::ChainFrozen {
            chain: source_chain.name,
        }));
    }

    if msgs.iter().any(|msg| msg.cc_id.chain != source_chain.name) {
        return Err(report!(Error::WrongSourceChain));
    }

    verify_msg_ids(&msgs, &source_chain.msg_id_format)?;

    Ok(msgs)
}

pub fn route_messages(
    storage: &dyn Storage,
    sender: Addr,
    msgs: Vec<Message>,
) -> error_stack::Result<Response, Error> {
    ensure!(state::is_enabled(store.storage()), Error::RoutingDisabled);

    let config = state::load_config(storage)?;

    let msgs = validate_msgs(storage, config.clone(), &sender, msgs)?;

    let wasm_msgs = msgs
        .iter()
        .group_by(|msg| msg.destination_chain.to_owned())
        .into_iter()
        .map(|(destination_chain, msgs)| {
            let gateway = match state::load_chain_by_chain_name(storage, &destination_chain)? {
                Some(destination_chain) if destination_chain.outgoing_frozen() => {
                    return Err(report!(Error::ChainFrozen {
                        chain: destination_chain.name,
                    }));
                }
                Some(destination_chain) => destination_chain.gateway.address,
                // messages with unknown destination chains are routed to
                // the nexus gateway if the sender is not the nexus gateway
                // itself
                None if sender != config.nexus_gateway => config.nexus_gateway.clone(),
                _ => return Err(report!(Error::ChainNotFound)),
            };

            Ok(WasmMsg::Execute {
                contract_addr: gateway.to_string(),
                msg: to_json_binary(&gateway_api::msg::ExecuteMsg::RouteMessages(
                    msgs.cloned().collect(),
                ))
                .expect("must serialize message"),
                funds: vec![],
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Response::new()
        .add_messages(wasm_msgs)
        .add_events(msgs.into_iter().map(|msg| MessageRouted { msg }.into())))
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::Addr;
    use rand::{random, RngCore};

    use axelar_wasm_std::flagset::FlagSet;
    use axelar_wasm_std::msg_id::tx_hash_event_index::HexTxHashAndEventIndex;
    use router_api::error::Error;
    use router_api::{ChainEndpoint, ChainName, CrossChainId, Gateway, GatewayDirection, Message};

    use crate::contract::execute::route_messages;
    use crate::contract::instantiate;
    use crate::events::{ChainFrozen, ChainUnfrozen};
    use crate::msg::InstantiateMsg;
    use crate::state;
    use crate::state::chain_endpoints;
    use crate::state::Config;

    use super::{freeze_chains, unfreeze_chains};

    fn rand_message(source_chain: ChainName, destination_chain: ChainName) -> Message {
        let mut bytes = [0; 32];
        rand::thread_rng().fill_bytes(&mut bytes);

        let id = HexTxHashAndEventIndex {
            tx_hash: bytes,
            event_index: random::<u32>(),
        }
        .to_string();

        let mut bytes = [0; 20];
        rand::thread_rng().fill_bytes(&mut bytes);
        let source_address = format!("0x{}", hex::encode(bytes)).try_into().unwrap();

        let mut bytes = [0; 20];
        rand::thread_rng().fill_bytes(&mut bytes);
        let destination_address = format!("0x{}", hex::encode(bytes)).try_into().unwrap();

        let mut payload_hash = [0; 32];
        rand::thread_rng().fill_bytes(&mut payload_hash);

        Message {
            cc_id: CrossChainId {
                chain: source_chain,
                id: id.parse().unwrap(),
            },
            source_address,
            destination_chain,
            destination_address,
            payload_hash,
        }
    }

    #[test]
    fn route_messages_with_not_registered_source_chain() {
        let sender = Addr::unchecked("sender");
        let source_chain: ChainName = "ethereum".parse().unwrap();
        let destination_chain = "bitcoin".parse().unwrap();

        let mut deps = mock_dependencies();
        instantiate(deps.as_mut(), mock_env(), mock_info("admin", &[]), InstantiateMsg{
            admin_address: "admin".to_string(),
            governance_address: "governance".to_string(),
            nexus_gateway: "nexus_gateway".to_string(),
        }).unwrap();

        assert!(route_messages(
            deps.as_mut().storage,
            sender,
            vec![rand_message(source_chain, destination_chain)]
        )
        .is_err_and(move |err| { matches!(err.current_context(), Error::GatewayNotRegistered) }));
    }

    #[test]
    fn route_messages_with_frozen_source_chain() {
        let sender = Addr::unchecked("sender");
        let source_chain: ChainName = "ethereum".parse().unwrap();
        let destination_chain = "bitcoin".parse().unwrap();


        let mut deps = mock_dependencies();
        instantiate(deps.as_mut(), mock_env(), mock_info("admin", &[]), InstantiateMsg{
            admin_address: "admin".to_string(),
            governance_address: "governance".to_string(),
            nexus_gateway: "nexus_gateway".to_string(),
        }).unwrap();

        let chain_endpoint = ChainEndpoint {
            name: source_chain.clone(),
            gateway: Gateway {
                address: sender.clone(),
            },
            frozen_status: FlagSet::from(GatewayDirection::Incoming),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        };
        chain_endpoints()
            .save(deps.as_mut().storage, source_chain.clone(), &chain_endpoint)
            .unwrap();

        assert!(route_messages(
            deps.as_mut().storage,
            sender,
            vec![rand_message(source_chain.clone(), destination_chain)]
        )
        .is_err_and(move |err| {
            matches!(err.current_context(), Error::ChainFrozen { chain } if *chain == source_chain)
        }));
    }

    #[test]
    fn route_messages_with_wrong_source_chain() {
        let sender = Addr::unchecked("sender");
        let source_chain: ChainName = "ethereum".parse().unwrap();
        let destination_chain = "bitcoin".parse().unwrap();

        let mut deps = mock_dependencies();
        instantiate(deps.as_mut(), mock_env(), mock_info("admin", &[]), InstantiateMsg{
            admin_address: "admin".to_string(),
            governance_address: "governance".to_string(),
            nexus_gateway: "nexus_gateway".to_string(),
        }).unwrap();

        let chain_endpoint = ChainEndpoint {
            name: source_chain.clone(),
            gateway: Gateway {
                address: sender.clone(),
            },
            frozen_status: FlagSet::from(GatewayDirection::None),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        };
        chain_endpoints()
            .save(deps.as_mut().storage, source_chain.clone(), &chain_endpoint)
            .unwrap();

        assert!(route_messages(
            deps.as_mut().storage,
            sender,
            vec![rand_message("polygon".parse().unwrap(), destination_chain)]
        )
        .is_err_and(|err| { matches!(err.current_context(), Error::WrongSourceChain) }));
    }

    #[test]
    fn route_messages_with_frozen_destination_chain() {

        let sender = Addr::unchecked("sender");
        let source_chain: ChainName = "ethereum".parse().unwrap();
        let destination_chain: ChainName = "bitcoin".parse().unwrap();

        let mut deps = mock_dependencies();
        instantiate(deps.as_mut(), mock_env(), mock_info("admin", &[]), InstantiateMsg{
            admin_address: "admin".to_string(),
            governance_address: "governance".to_string(),
            nexus_gateway: "nexus_gateway".to_string(),
        }).unwrap();
        let source_chain_endpoint = ChainEndpoint {
            name: source_chain.clone(),
            gateway: Gateway {
                address: sender.clone(),
            },
            frozen_status: FlagSet::from(GatewayDirection::None),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        };
        chain_endpoints()
            .save(
                deps.as_mut().storage,
                source_chain.clone(),
                &source_chain_endpoint,
            )
            .unwrap();
        let destination_chain_endpoint = ChainEndpoint {
            name: destination_chain.clone(),
            gateway: Gateway {
                address: Addr::unchecked("destination"),
            },
            frozen_status: FlagSet::from(GatewayDirection::Bidirectional),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        };
        chain_endpoints()
            .save(
                deps.as_mut().storage,
                destination_chain.clone(),
                &destination_chain_endpoint,
            )
            .unwrap();

        assert!(route_messages(deps.as_mut().storage, sender, vec![rand_message(source_chain, destination_chain.clone())])
            .is_err_and(move |err| {
                matches!(err.current_context(), Error::ChainFrozen { chain } if *chain == destination_chain)
            }));
    }

    #[test]
    fn route_messages_from_non_nexus_with_invalid_message_id() {
        let sender = Addr::unchecked("sender");
        let source_chain: ChainName = "ethereum".parse().unwrap();
        let destination_chain: ChainName = "bitcoin".parse().unwrap();

        let mut deps = mock_dependencies();
        instantiate(deps.as_mut(), mock_env(), mock_info("admin", &[]), InstantiateMsg{
            admin_address: "admin".to_string(),
            governance_address: "governance".to_string(),
            nexus_gateway: "nexus_gateway".to_string(),
        }).unwrap();

        let source_chain_endpoint = ChainEndpoint {
            name: source_chain.clone(),
            gateway: Gateway {
                address: sender.clone(),
            },
            frozen_status: FlagSet::from(GatewayDirection::None),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        };
        chain_endpoints()
            .save(
                deps.as_mut().storage,
                source_chain.clone(),
                &source_chain_endpoint,
            )
            .unwrap();

        let mut msg = rand_message(source_chain, destination_chain.clone());
        msg.cc_id.id = "foobar".try_into().unwrap();
        assert!(route_messages(deps.as_mut().storage, sender, vec![msg])
            .is_err_and(move |err| { matches!(err.current_context(), Error::InvalidMessageId) }));
    }

    #[test]
    fn route_messages_from_nexus_with_invalid_message_id() {
        let sender = config.nexus_gateway.clone();
        let source_chain: ChainName = "ethereum".parse().unwrap();
        let destination_chain: ChainName = "bitcoin".parse().unwrap();

        let mut deps = mock_dependencies();
        instantiate(deps.as_mut(), mock_env(), mock_info("admin", &[]), InstantiateMsg{
            admin_address: "admin".to_string(),
            governance_address: "governance".to_string(),
            nexus_gateway: "nexus_gateway".to_string(),
        }).unwrap();

        let mut msg = rand_message(source_chain, destination_chain.clone());
        msg.cc_id.id = "foobar".try_into().unwrap();
        assert!(route_messages(deps.as_mut().storage, sender, vec![msg])
            .is_err_and(move |err| { matches!(err.current_context(), Error::InvalidMessageId) }));
    }

    #[test]
    fn route_messages_from_non_nexus_with_incorrect_message_id_format() {

        let sender = Addr::unchecked("sender");
        let source_chain: ChainName = "ethereum".parse().unwrap();
        let destination_chain: ChainName = "bitcoin".parse().unwrap();

        let mut deps = mock_dependencies();
        instantiate(deps.as_mut(), mock_env(), mock_info("admin", &[]), InstantiateMsg{
            admin_address: "admin".to_string(),
            governance_address: "governance".to_string(),
            nexus_gateway: "nexus_gateway".to_string(),
        }).unwrap();

        let source_chain_endpoint = ChainEndpoint {
            name: source_chain.clone(),
            gateway: Gateway {
                address: sender.clone(),
            },
            frozen_status: FlagSet::from(GatewayDirection::None),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::Base58TxDigestAndEventIndex,
        };
        chain_endpoints()
            .save(
                deps.as_mut().storage,
                source_chain.clone(),
                &source_chain_endpoint,
            )
            .unwrap();

        let mut msg = rand_message(source_chain, destination_chain.clone());
        msg.cc_id.id = HexTxHashAndEventIndex {
            tx_hash: [0; 32],
            event_index: 0,
        }
        .to_string()
        .try_into()
        .unwrap();
        assert!(route_messages(deps.as_mut().storage, sender, vec![msg])
            .is_err_and(move |err| { matches!(err.current_context(), Error::InvalidMessageId) }));
    }

    #[test]
    fn route_messages_from_non_nexus_to_non_nexus() {
        let sender = Addr::unchecked("sender");
        let source_chain: ChainName = "ethereum".parse().unwrap();
        let destination_chain_1: ChainName = "bitcoin".parse().unwrap();
        let destination_chain_2: ChainName = "polygon".parse().unwrap();

        let mut deps = mock_dependencies();
        instantiate(deps.as_mut(), mock_env(), mock_info("admin", &[]), InstantiateMsg{
            admin_address: "admin".to_string(),
            governance_address: "governance".to_string(),
            nexus_gateway: "nexus_gateway".to_string(),
        }).unwrap();

        let source_chain_endpoint = ChainEndpoint {
            name: source_chain.clone(),
            gateway: Gateway {
                address: sender.clone(),
            },
            frozen_status: FlagSet::from(GatewayDirection::None),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        };
        chain_endpoints()
            .save(
                deps.as_mut().storage,
                source_chain.clone(),
                &source_chain_endpoint,
            )
            .unwrap();
        let destination_chain_endpoint_1 = ChainEndpoint {
            name: destination_chain_1.clone(),
            gateway: Gateway {
                address: Addr::unchecked("destination_1"),
            },
            frozen_status: FlagSet::from(GatewayDirection::None),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        };
        chain_endpoints()
            .save(
                deps.as_mut().storage,
                destination_chain_1.clone(),
                &destination_chain_endpoint_1,
            )
            .unwrap();
        let destination_chain_endpoint_2 = ChainEndpoint {
            name: destination_chain_2.clone(),
            gateway: Gateway {
                address: Addr::unchecked("destination_2"),
            },
            frozen_status: FlagSet::from(GatewayDirection::None),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        };
        chain_endpoints()
            .save(
                deps.as_mut().storage,
                destination_chain_2.clone(),
                &destination_chain_endpoint_2,
            )
            .unwrap();

        assert!(route_messages(
            deps.as_mut().storage,
            sender,
            vec![
                rand_message(source_chain.clone(), destination_chain_1.clone()),
                rand_message(source_chain.clone(), destination_chain_1.clone()),
                rand_message(source_chain.clone(), destination_chain_1.clone()),
                rand_message(source_chain.clone(), destination_chain_2.clone()),
            ]
        )
        .is_ok_and(|res| { res.messages.len() == 2 }));
    }

    #[test]
    fn route_messages_from_nexus_to_registered_chains() {
        let config = Config {
            admin: Addr::unchecked("admin"),
            governance: Addr::unchecked("governance"),
            nexus_gateway: Addr::unchecked("nexus_gateway"),
        };
        let sender = config.nexus_gateway.clone();
        let source_chain: ChainName = "ethereum".parse().unwrap();
        let destination_chain_1: ChainName = "bitcoin".parse().unwrap();
        let destination_chain_2: ChainName = "polygon".parse().unwrap();

        let mut deps = mock_dependencies();
        instantiate(deps.as_mut(), mock_env(), mock_info("admin", &[]), InstantiateMsg{
            admin_address: "admin".to_string(),
            governance_address: "governance".to_string(),
            nexus_gateway: "nexus_gateway".to_string(),
        }).unwrap();

        let destination_chain_endpoint_1 = ChainEndpoint {
            name: destination_chain_1.clone(),
            gateway: Gateway {
                address: sender.clone(),
            },
            frozen_status: FlagSet::from(GatewayDirection::None),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        };
        chain_endpoints()
            .save(
                deps.as_mut().storage,
                destination_chain_1.clone(),
                &destination_chain_endpoint_1,
            )
            .unwrap();
        let destination_chain_endpoint_2 = ChainEndpoint {
            name: destination_chain_2.clone(),
            gateway: Gateway {
                address: sender.clone(),
            },
            frozen_status: FlagSet::from(GatewayDirection::None),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        };
        chain_endpoints()
            .save(
                deps.as_mut().storage,
                destination_chain_2.clone(),
                &destination_chain_endpoint_2,
            )
            .unwrap();

        assert!(route_messages(
            deps.as_mut().storage,
            sender,
            vec![
                rand_message(source_chain.clone(), destination_chain_1.clone()),
                rand_message(source_chain.clone(), destination_chain_1.clone()),
                rand_message(source_chain.clone(), destination_chain_1.clone()),
                rand_message(source_chain.clone(), destination_chain_2.clone()),
            ]
        )
        .is_ok_and(|res| { res.messages.len() == 2 }));
    }

    #[test]
    fn route_messages_from_nexus_to_non_registered_chains() {
        let sender = config.nexus_gateway.clone();
        let source_chain: ChainName = "ethereum".parse().unwrap();
        let destination_chain: ChainName = "bitcoin".parse().unwrap();

        let mut deps = mock_dependencies();
        instantiate(deps.as_mut(), mock_env(), mock_info("admin", &[]), InstantiateMsg{
            admin_address: "admin".to_string(),
            governance_address: "governance".to_string(),
            nexus_gateway: "nexus_gateway".to_string(),
        }).unwrap();

        assert!(route_messages(
            deps.as_mut().storage,
            sender,
            vec![rand_message(
                source_chain.clone(),
                destination_chain.clone()
            )]
        )
        .is_err_and(|err| { matches!(err.current_context(), Error::ChainNotFound) }));
    }

    #[test]
    fn route_messages_from_registered_chain_to_nexus() {
        let sender = Addr::unchecked("sender");
        let source_chain: ChainName = "ethereum".parse().unwrap();
        let destination_chain: ChainName = "bitcoin".parse().unwrap();

        let mut deps = mock_dependencies();
        instantiate(deps.as_mut(), mock_env(), mock_info("admin", &[]), InstantiateMsg{
            admin_address: "admin".to_string(),
            governance_address: "governance".to_string(),
            nexus_gateway: "nexus_gateway".to_string(),
        }).unwrap();

        let source_chain_endpoint = ChainEndpoint {
            name: source_chain.clone(),
            gateway: Gateway {
                address: sender.clone(),
            },
            frozen_status: FlagSet::from(GatewayDirection::None),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        };
        chain_endpoints()
            .save(
                deps.as_mut().storage,
                source_chain.clone(),
                &source_chain_endpoint,
            )
            .unwrap();

        assert!(route_messages(
            deps.as_mut().storage,
            sender,
            vec![rand_message(
                source_chain.clone(),
                destination_chain.clone()
            )]
        )
        .is_ok_and(|res| { res.messages.len() == 1 }));
    }

    #[test]
    fn multiple_freeze_unfreeze_causes_no_arithmetic_side_effect() {
        let mut deps = mock_dependencies();
        let chain: ChainName = "ethereum".parse().unwrap();

        chain_endpoints()
            .save(
                deps.as_mut().storage,
                chain.clone(),
                &ChainEndpoint {
                    name: chain.clone(),
                    gateway: Gateway {
                        address: Addr::unchecked("gateway"),
                    },
                    frozen_status: FlagSet::from(GatewayDirection::None),
                    msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
                },
            )
            .unwrap();

        // freezing twice produces same result
        freeze_chains(
            deps.as_mut(),
            HashMap::from([(chain.clone(), GatewayDirection::Incoming)]),
        )
        .unwrap();
        freeze_chains(
            deps.as_mut(),
            HashMap::from([(chain.clone(), GatewayDirection::Incoming)]),
        )
        .unwrap();

        assert_chain_endpoint_frozen_status(
            deps.as_mut().storage,
            chain.clone(),
            FlagSet::from(GatewayDirection::Incoming),
        );

        freeze_chains(
            deps.as_mut(),
            HashMap::from([(chain.clone(), GatewayDirection::Bidirectional)]),
        )
        .unwrap();
        freeze_chains(
            deps.as_mut(),
            HashMap::from([(chain.clone(), GatewayDirection::Bidirectional)]),
        )
        .unwrap();

        assert_chain_endpoint_frozen_status(
            deps.as_mut().storage,
            chain.clone(),
            FlagSet::from(GatewayDirection::Bidirectional),
        );

        // unfreezing twice produces same result
        unfreeze_chains(
            deps.as_mut(),
            HashMap::from([(chain.clone(), GatewayDirection::Outgoing)]),
        )
        .unwrap();
        unfreeze_chains(
            deps.as_mut(),
            HashMap::from([(chain.clone(), GatewayDirection::Outgoing)]),
        )
        .unwrap();

        assert_chain_endpoint_frozen_status(
            deps.as_mut().storage,
            chain.clone(),
            FlagSet::from(GatewayDirection::Incoming),
        );

        unfreeze_chains(
            deps.as_mut(),
            HashMap::from([(chain.clone(), GatewayDirection::Bidirectional)]),
        )
        .unwrap();
        unfreeze_chains(
            deps.as_mut(),
            HashMap::from([(chain.clone(), GatewayDirection::Bidirectional)]),
        )
        .unwrap();

        assert_chain_endpoint_frozen_status(
            deps.as_mut().storage,
            chain.clone(),
            FlagSet::from(GatewayDirection::None),
        );
    }

    #[test]
    fn freezing_unfreezing_chain_emits_correct_event() {
        let mut deps = mock_dependencies();
        let chain: ChainName = "ethereum".parse().unwrap();

        chain_endpoints()
            .save(
                deps.as_mut().storage,
                chain.clone(),
                &ChainEndpoint {
                    name: chain.clone(),
                    gateway: Gateway {
                        address: Addr::unchecked("gateway"),
                    },
                    frozen_status: FlagSet::from(GatewayDirection::None),
                    msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
                },
            )
            .unwrap();

        let res = freeze_chains(
            deps.as_mut(),
            HashMap::from([(chain.clone(), GatewayDirection::Incoming)]),
        )
        .unwrap();

        assert_eq!(res.events.len(), 1);
        assert!(res.events.contains(
            &ChainFrozen {
                name: chain.clone(),
                direction: GatewayDirection::Incoming,
            }
            .into()
        ));

        let res = unfreeze_chains(
            deps.as_mut(),
            HashMap::from([(chain.clone(), GatewayDirection::Incoming)]),
        )
        .unwrap();

        assert_eq!(res.events.len(), 1);
        assert!(res.events.contains(
            &ChainUnfrozen {
                name: chain.clone(),
                direction: GatewayDirection::Incoming,
            }
            .into()
        ));
    }

    fn assert_chain_endpoint_frozen_status(
        storage: &dyn Storage,
        chain: ChainName,
        expected: FlagSet<GatewayDirection>,
    ) {
        let status = chain_endpoints()
            .load(storage, chain.clone())
            .unwrap()
            .frozen_status;
        assert_eq!(status, expected);
    }
}
