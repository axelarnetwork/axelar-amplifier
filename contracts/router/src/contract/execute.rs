use std::collections::HashMap;
use std::vec;

use axelar_core_std::nexus;
use axelar_wasm_std::flagset::FlagSet;
use axelar_wasm_std::killswitch;
use axelar_wasm_std::msg_id::{self, MessageIdFormat};
use cosmwasm_std::{
    to_json_binary, Addr, Event, QuerierWrapper, Response, StdResult, Storage, WasmMsg,
};
use error_stack::{bail, ensure, report, Report, ResultExt};
use itertools::Itertools;
use router_api::error::Error;
use router_api::{ChainEndpoint, ChainName, Gateway, GatewayDirection, Message};

use crate::events::GatewayInfo;
use crate::state::{chain_endpoints, Config};
use crate::{state, Event as RouterEvent};

pub fn register_chain(
    storage: &mut dyn Storage,
    querier: QuerierWrapper,
    name: ChainName,
    gateway: Addr,
    msg_id_format: MessageIdFormat,
) -> error_stack::Result<Response, Error> {
    if find_chain_for_gateway(storage, &gateway)
        .change_context(Error::StoreFailure)?
        .is_some()
    {
        bail!(Error::GatewayAlreadyRegistered)
    }

    let client: nexus::Client = client::CosmosClient::new(querier).into();
    if client
        .is_chain_registered(&name)
        .change_context(Error::Nexus)?
    {
        Err(Report::new(Error::ChainAlreadyExists))
            .attach_printable(format!("chain {} already exists in core", name))?
    }

    chain_endpoints().update(storage, name.clone(), |chain| match chain {
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
    Ok(Response::new().add_event(RouterEvent::ChainRegistered { name, gateway }))
}

pub fn find_chain_for_gateway(
    storage: &dyn Storage,
    contract_address: &Addr,
) -> StdResult<Option<ChainEndpoint>> {
    chain_endpoints()
        .idx
        .gateway
        .load_chain_by_gateway(storage, contract_address)
}

pub fn upgrade_gateway(
    storage: &mut dyn Storage,
    chain: ChainName,
    contract_address: Addr,
) -> Result<Response, Error> {
    if find_chain_for_gateway(storage, &contract_address)?.is_some() {
        return Err(Error::GatewayAlreadyRegistered);
    }
    chain_endpoints().update(storage, chain.clone(), |chain| match chain {
        None => Err(Error::ChainNotFound),
        Some(mut chain) => {
            chain.gateway.address = contract_address.clone();
            Ok(chain)
        }
    })?;
    Ok(
        Response::new().add_event(RouterEvent::GatewayUpgraded(GatewayInfo {
            chain,
            gateway_address: contract_address,
        })),
    )
}

fn freeze_specific_chain(
    storage: &mut dyn Storage,
    chain: ChainName,
    direction: GatewayDirection,
) -> Result<RouterEvent, Error> {
    chain_endpoints().update(storage, chain.clone(), |chain| match chain {
        None => Err(Error::ChainNotFound),
        Some(mut chain) => {
            *chain.frozen_status |= direction;
            Ok(chain)
        }
    })?;

    Ok(RouterEvent::ChainFrozen {
        name: chain,
        direction,
    })
}

pub fn freeze_chains(
    storage: &mut dyn Storage,
    chains: HashMap<ChainName, GatewayDirection>,
) -> Result<Response, Error> {
    let events: Vec<_> = chains
        .into_iter()
        .map(|(chain, direction)| freeze_specific_chain(storage, chain, direction))
        .map_ok(Event::from)
        .try_collect()?;

    Ok(Response::new().add_events(events))
}

#[allow(clippy::arithmetic_side_effects)] // flagset operations don't cause under/overflows
fn unfreeze_specific_chain(
    storage: &mut dyn Storage,
    chain: ChainName,
    direction: GatewayDirection,
) -> Result<RouterEvent, Error> {
    chain_endpoints().update(storage, chain.clone(), |chain| match chain {
        None => Err(Error::ChainNotFound),
        Some(mut chain) => {
            *chain.frozen_status -= direction;
            Ok(chain)
        }
    })?;

    Ok(RouterEvent::ChainUnfrozen {
        name: chain,
        direction,
    })
}

pub fn unfreeze_chains(
    storage: &mut dyn Storage,
    chains: HashMap<ChainName, GatewayDirection>,
) -> Result<Response, Error> {
    let events: Vec<_> = chains
        .into_iter()
        .map(|(chain, direction)| unfreeze_specific_chain(storage, chain, direction))
        .map_ok(Event::from)
        .try_collect()?;

    Ok(Response::new().add_events(events))
}

pub fn disable_routing(storage: &mut dyn Storage) -> Result<Response, Error> {
    killswitch::engage(storage, RouterEvent::RoutingDisabled).map_err(|err| err.into())
}

pub fn enable_routing(storage: &mut dyn Storage) -> Result<Response, Error> {
    killswitch::disengage(storage, RouterEvent::RoutingEnabled).map_err(|err| err.into())
}

fn verify_msg_ids(
    msgs: &[Message],
    expected_format: &MessageIdFormat,
) -> Result<(), error_stack::Report<Error>> {
    msgs.iter()
        .try_for_each(|msg| msg_id::verify_msg_id(&msg.cc_id.message_id, expected_format))
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
    if sender == config.axelarnet_gateway {
        verify_msg_ids(&msgs, &MessageIdFormat::HexTxHashAndEventIndex)?;
        return Ok(msgs);
    }

    let source_chain = state::load_chain_by_gateway(storage, sender)?;
    if source_chain.incoming_frozen() {
        return Err(report!(Error::ChainFrozen {
            chain: source_chain.name,
        }));
    }

    if msgs
        .iter()
        .any(|msg| msg.cc_id.source_chain != source_chain.name)
    {
        return Err(report!(Error::WrongSourceChain));
    }

    verify_msg_ids(&msgs, &source_chain.msg_id_format)?;

    Ok(msgs)
}

pub fn route_messages(
    storage: &dyn Storage,
    querier: QuerierWrapper,
    sender: Addr,
    msgs: Vec<Message>,
) -> error_stack::Result<Response, Error> {
    ensure!(
        killswitch::is_contract_active(storage),
        Error::RoutingDisabled
    );

    let config = state::load_config(storage)?;
    let client: nexus::Client = client::CosmosClient::new(querier).into();

    let msgs = validate_msgs(storage, config.clone(), &sender, msgs)?;

    let wasm_msgs = msgs
        .iter()
        .chunk_by(|msg| msg.destination_chain.to_owned())
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
                // the axelarnet gateway if the sender is not the nexus gateway
                // itself
                None if client
                    .is_chain_registered(&destination_chain)
                    .change_context(Error::Nexus)? =>
                {
                    config.axelarnet_gateway.clone()
                }
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
        .add_events(msgs.into_iter().map(RouterEvent::MessageRouted)))
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use axelar_core_std::nexus::test_utils::reply_with_is_chain_registered;
    use axelar_wasm_std::assert_err_contains;
    use axelar_wasm_std::flagset::FlagSet;
    use axelar_wasm_std::msg_id::{HexTxHashAndEventIndex, MessageIdFormat};
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use cosmwasm_std::{QuerierWrapper, Storage};
    use rand::{random, RngCore};
    use router_api::error::Error;
    use router_api::{
        chain_name, cosmos_addr, ChainEndpoint, ChainName, CrossChainId, Gateway, GatewayDirection,
        Message,
    };

    use super::{freeze_chains, register_chain, unfreeze_chains};
    use crate::contract::execute::route_messages;
    use crate::contract::instantiate;
    use crate::msg::InstantiateMsg;
    use crate::state::chain_endpoints;
    use crate::Event as RouterEvent;

    const AXELARNET_GATEWAY: &str = "axelarnet_gateway";
    const COORDINATOR: &str = "coordinator";
    const SENDER: &str = "sender";
    const ADMIN: &str = "admin";
    const GOVERNANCE: &str = "governance";
    const GATEWAY: &str = "gateway";
    const ETHEREUM: &str = "ethereum";
    const BITCOIN: &str = "bitcoin";
    const POLYGON: &str = "polygon";

    fn rand_message(source_chain: ChainName, destination_chain: ChainName) -> Message {
        let mut bytes = [0; 32];
        rand::thread_rng().fill_bytes(&mut bytes);

        let id = HexTxHashAndEventIndex {
            tx_hash: bytes,
            event_index: random::<u64>(),
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
            cc_id: CrossChainId::new(source_chain, id).unwrap(),
            source_address,
            destination_chain,
            destination_address,
            payload_hash,
        }
    }

    #[test]
    fn route_messages_with_not_registered_source_chain() {
        let mut deps = mock_dependencies();
        let sender = cosmos_addr!(SENDER);
        let source_chain = chain_name!(ETHEREUM);
        let destination_chain = chain_name!(BITCOIN);

        instantiate(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!(ADMIN), &[]),
            InstantiateMsg {
                admin_address: cosmos_addr!(ADMIN).to_string(),
                governance_address: cosmos_addr!(GOVERNANCE).to_string(),
                axelarnet_gateway: cosmos_addr!(AXELARNET_GATEWAY).to_string(),
                coordinator_address: cosmos_addr!(COORDINATOR).to_string(),
            },
        )
        .unwrap();

        assert!(route_messages(
            &deps.storage,
            QuerierWrapper::new(&deps.querier),
            sender,
            vec![rand_message(source_chain, destination_chain)]
        )
        .is_err_and(move |err| { matches!(err.current_context(), Error::GatewayNotRegistered) }));
    }

    #[test]
    fn route_messages_with_frozen_source_chain() {
        let mut deps = mock_dependencies();
        let sender = cosmos_addr!(SENDER);
        let source_chain = chain_name!(ETHEREUM);
        let destination_chain = chain_name!(BITCOIN);

        instantiate(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!(ADMIN), &[]),
            InstantiateMsg {
                admin_address: cosmos_addr!(ADMIN).to_string(),
                governance_address: cosmos_addr!(GOVERNANCE).to_string(),
                axelarnet_gateway: cosmos_addr!(AXELARNET_GATEWAY).to_string(),
                coordinator_address: cosmos_addr!(COORDINATOR).to_string(),
            },
        )
        .unwrap();

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
            &deps.storage,
            QuerierWrapper::new(&deps.querier),
            sender,
            vec![rand_message(source_chain.clone(), destination_chain)]
        )
        .is_err_and(move |err| {
            matches!(err.current_context(), Error::ChainFrozen { chain } if *chain == source_chain)
        }));
    }

    #[test]
    fn route_messages_with_wrong_source_chain() {
        let mut deps = mock_dependencies();
        let sender = cosmos_addr!(SENDER);
        let source_chain = chain_name!(ETHEREUM);
        let destination_chain = chain_name!(BITCOIN);

        instantiate(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!(ADMIN), &[]),
            InstantiateMsg {
                admin_address: cosmos_addr!(ADMIN).to_string(),
                governance_address: cosmos_addr!(GOVERNANCE).to_string(),
                axelarnet_gateway: cosmos_addr!(AXELARNET_GATEWAY).to_string(),
                coordinator_address: cosmos_addr!(COORDINATOR).to_string(),
            },
        )
        .unwrap();

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
            &deps.storage,
            QuerierWrapper::new(&deps.querier),
            sender,
            vec![rand_message(chain_name!(POLYGON), destination_chain)]
        )
        .is_err_and(|err| { matches!(err.current_context(), Error::WrongSourceChain) }));
    }

    #[test]
    fn route_messages_with_frozen_destination_chain() {
        let mut deps = mock_dependencies();
        let sender = cosmos_addr!(SENDER);
        let source_chain = chain_name!(ETHEREUM);
        let destination_chain = chain_name!(BITCOIN);

        instantiate(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!(ADMIN), &[]),
            InstantiateMsg {
                admin_address: cosmos_addr!(ADMIN).to_string(),
                governance_address: cosmos_addr!(GOVERNANCE).to_string(),
                axelarnet_gateway: cosmos_addr!(AXELARNET_GATEWAY).to_string(),
                coordinator_address: cosmos_addr!(COORDINATOR).to_string(),
            },
        )
        .unwrap();
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
                address: cosmos_addr!("destination"),
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

        assert!(route_messages(&deps.storage, QuerierWrapper::new(&deps.querier), sender, vec![rand_message(source_chain, destination_chain.clone())])
            .is_err_and(move |err| {
                matches!(err.current_context(), Error::ChainFrozen { chain } if *chain == destination_chain)
            }));
    }

    #[test]
    fn route_messages_from_non_nexus_with_invalid_message_id() {
        let mut deps = mock_dependencies();
        let sender = cosmos_addr!(SENDER);
        let source_chain = chain_name!(ETHEREUM);
        let destination_chain = chain_name!(BITCOIN);

        instantiate(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!(ADMIN), &[]),
            InstantiateMsg {
                admin_address: cosmos_addr!(ADMIN).to_string(),
                governance_address: cosmos_addr!(GOVERNANCE).to_string(),
                axelarnet_gateway: cosmos_addr!(AXELARNET_GATEWAY).to_string(),
                coordinator_address: cosmos_addr!(COORDINATOR).to_string(),
            },
        )
        .unwrap();

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

        let mut msg = rand_message(source_chain.clone(), destination_chain.clone());
        msg.cc_id = CrossChainId::new(source_chain, "foobar").unwrap();
        assert_err_contains!(
            route_messages(
                &deps.storage,
                QuerierWrapper::new(&deps.querier),
                sender,
                vec![msg]
            ),
            Error,
            Error::InvalidMessageId
        );
    }

    #[test]
    fn route_messages_from_nexus_with_invalid_message_id() {
        let mut deps = mock_dependencies();
        let sender = cosmos_addr!(AXELARNET_GATEWAY);
        let source_chain = chain_name!(ETHEREUM);
        let destination_chain = chain_name!(BITCOIN);

        instantiate(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!(ADMIN), &[]),
            InstantiateMsg {
                admin_address: cosmos_addr!(ADMIN).to_string(),
                governance_address: cosmos_addr!(GOVERNANCE).to_string(),
                axelarnet_gateway: cosmos_addr!(AXELARNET_GATEWAY).to_string(),
                coordinator_address: cosmos_addr!(COORDINATOR).to_string(),
            },
        )
        .unwrap();

        let mut msg = rand_message(source_chain.clone(), destination_chain.clone());
        msg.cc_id = CrossChainId::new(source_chain, "foobar").unwrap();
        assert_err_contains!(
            route_messages(
                &deps.storage,
                QuerierWrapper::new(&deps.querier),
                sender,
                vec![msg]
            ),
            Error,
            Error::InvalidMessageId
        );
    }

    #[test]
    fn route_messages_from_non_nexus_with_incorrect_message_id_format() {
        let mut deps = mock_dependencies();
        let sender = cosmos_addr!(SENDER);
        let source_chain = chain_name!(ETHEREUM);
        let destination_chain = chain_name!(BITCOIN);

        instantiate(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!(ADMIN), &[]),
            InstantiateMsg {
                admin_address: cosmos_addr!(ADMIN).to_string(),
                governance_address: cosmos_addr!(GOVERNANCE).to_string(),
                axelarnet_gateway: cosmos_addr!(AXELARNET_GATEWAY).to_string(),
                coordinator_address: cosmos_addr!(COORDINATOR).to_string(),
            },
        )
        .unwrap();

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

        let mut msg = rand_message(source_chain.clone(), destination_chain.clone());
        msg.cc_id = CrossChainId::new(
            source_chain,
            HexTxHashAndEventIndex {
                tx_hash: [0; 32],
                event_index: 0,
            }
            .to_string()
            .as_str(),
        )
        .unwrap();

        assert_err_contains!(
            route_messages(
                &deps.storage,
                QuerierWrapper::new(&deps.querier),
                sender,
                vec![msg]
            ),
            Error,
            Error::InvalidMessageId
        );
    }

    #[test]
    fn route_messages_from_non_nexus_to_non_nexus() {
        let mut deps = mock_dependencies();
        let sender = cosmos_addr!(SENDER);
        let source_chain = chain_name!(ETHEREUM);
        let destination_chain_1 = chain_name!(BITCOIN);
        let destination_chain_2 = chain_name!(POLYGON);

        instantiate(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!(ADMIN), &[]),
            InstantiateMsg {
                admin_address: cosmos_addr!(ADMIN).to_string(),
                governance_address: cosmos_addr!(GOVERNANCE).to_string(),
                axelarnet_gateway: cosmos_addr!(AXELARNET_GATEWAY).to_string(),
                coordinator_address: cosmos_addr!(COORDINATOR).to_string(),
            },
        )
        .unwrap();

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
                address: cosmos_addr!("destination_1"),
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
                address: cosmos_addr!("destination_2"),
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
            &deps.storage,
            QuerierWrapper::new(&deps.querier),
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
        let mut deps = mock_dependencies();
        let sender = cosmos_addr!(AXELARNET_GATEWAY);
        let source_chain = chain_name!(ETHEREUM);
        let destination_chain_1 = chain_name!(BITCOIN);
        let destination_chain_2 = chain_name!(POLYGON);

        instantiate(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!(ADMIN), &[]),
            InstantiateMsg {
                admin_address: cosmos_addr!(ADMIN).to_string(),
                governance_address: cosmos_addr!(GOVERNANCE).to_string(),
                axelarnet_gateway: cosmos_addr!(AXELARNET_GATEWAY).to_string(),
                coordinator_address: cosmos_addr!(COORDINATOR).to_string(),
            },
        )
        .unwrap();

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
            &deps.storage,
            QuerierWrapper::new(&deps.querier),
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
        let mut deps = mock_dependencies();
        deps.querier = deps
            .querier
            .with_custom_handler(reply_with_is_chain_registered(false));

        let sender = cosmos_addr!(AXELARNET_GATEWAY);
        let source_chain = chain_name!(ETHEREUM);
        let destination_chain = chain_name!(BITCOIN);

        instantiate(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!(ADMIN), &[]),
            InstantiateMsg {
                admin_address: cosmos_addr!(ADMIN).to_string(),
                governance_address: cosmos_addr!(GOVERNANCE).to_string(),
                axelarnet_gateway: cosmos_addr!(AXELARNET_GATEWAY).to_string(),
                coordinator_address: cosmos_addr!(COORDINATOR).to_string(),
            },
        )
        .unwrap();

        assert!(route_messages(
            &deps.storage,
            QuerierWrapper::new(&deps.querier),
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
        let mut deps = mock_dependencies();
        deps.querier = deps
            .querier
            .with_custom_handler(reply_with_is_chain_registered(true));
        let sender = cosmos_addr!(SENDER);
        let source_chain = chain_name!(ETHEREUM);
        let destination_chain = chain_name!(BITCOIN);

        instantiate(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!(ADMIN), &[]),
            InstantiateMsg {
                admin_address: cosmos_addr!(ADMIN).to_string(),
                governance_address: cosmos_addr!(GOVERNANCE).to_string(),
                axelarnet_gateway: cosmos_addr!(AXELARNET_GATEWAY).to_string(),
                coordinator_address: cosmos_addr!(COORDINATOR).to_string(),
            },
        )
        .unwrap();

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
            &deps.storage,
            QuerierWrapper::new(&deps.querier),
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
        let chain = chain_name!(ETHEREUM);

        chain_endpoints()
            .save(
                deps.as_mut().storage,
                chain.clone(),
                &ChainEndpoint {
                    name: chain.clone(),
                    gateway: Gateway {
                        address: cosmos_addr!(GATEWAY),
                    },
                    frozen_status: FlagSet::from(GatewayDirection::None),
                    msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
                },
            )
            .unwrap();

        // freezing twice produces same result
        freeze_chains(
            deps.as_mut().storage,
            HashMap::from([(chain.clone(), GatewayDirection::Incoming)]),
        )
        .unwrap();
        freeze_chains(
            deps.as_mut().storage,
            HashMap::from([(chain.clone(), GatewayDirection::Incoming)]),
        )
        .unwrap();

        assert_chain_endpoint_frozen_status(
            deps.as_mut().storage,
            chain.clone(),
            FlagSet::from(GatewayDirection::Incoming),
        );

        freeze_chains(
            deps.as_mut().storage,
            HashMap::from([(chain.clone(), GatewayDirection::Bidirectional)]),
        )
        .unwrap();
        freeze_chains(
            deps.as_mut().storage,
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
            deps.as_mut().storage,
            HashMap::from([(chain.clone(), GatewayDirection::Outgoing)]),
        )
        .unwrap();
        unfreeze_chains(
            deps.as_mut().storage,
            HashMap::from([(chain.clone(), GatewayDirection::Outgoing)]),
        )
        .unwrap();

        assert_chain_endpoint_frozen_status(
            deps.as_mut().storage,
            chain.clone(),
            FlagSet::from(GatewayDirection::Incoming),
        );

        unfreeze_chains(
            deps.as_mut().storage,
            HashMap::from([(chain.clone(), GatewayDirection::Bidirectional)]),
        )
        .unwrap();
        unfreeze_chains(
            deps.as_mut().storage,
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
        let chain = chain_name!(ETHEREUM);

        chain_endpoints()
            .save(
                deps.as_mut().storage,
                chain.clone(),
                &ChainEndpoint {
                    name: chain.clone(),
                    gateway: Gateway {
                        address: cosmos_addr!(GATEWAY),
                    },
                    frozen_status: FlagSet::from(GatewayDirection::None),
                    msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
                },
            )
            .unwrap();

        let res = freeze_chains(
            deps.as_mut().storage,
            HashMap::from([(chain.clone(), GatewayDirection::Incoming)]),
        )
        .unwrap();

        assert_eq!(res.events.len(), 1);
        assert!(res.events.contains(
            &RouterEvent::ChainFrozen {
                name: chain.clone(),
                direction: GatewayDirection::Incoming,
            }
            .into()
        ));

        let res = unfreeze_chains(
            deps.as_mut().storage,
            HashMap::from([(chain.clone(), GatewayDirection::Incoming)]),
        )
        .unwrap();

        assert_eq!(res.events.len(), 1);
        assert!(res.events.contains(
            &RouterEvent::ChainUnfrozen {
                name: chain.clone(),
                direction: GatewayDirection::Incoming,
            }
            .into()
        ));
    }

    #[test]
    fn register_chain_with_duplicate_chain_name_in_core() {
        let mut deps = mock_dependencies();
        deps.querier = deps
            .querier
            .with_custom_handler(reply_with_is_chain_registered(true));

        assert_err_contains!(
            register_chain(
                &mut deps.storage,
                QuerierWrapper::new(&deps.querier),
                chain_name!(ETHEREUM),
                cosmos_addr!(GATEWAY),
                MessageIdFormat::HexTxHashAndEventIndex
            ),
            Error,
            Error::ChainAlreadyExists
        );
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
