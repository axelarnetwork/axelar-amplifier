use std::vec;

use axelar_wasm_std::msg_id::{self, MessageIdFormat};
use cosmwasm_std::{to_binary, Addr, DepsMut, MessageInfo, Response, StdResult, WasmMsg};
use error_stack::{report, ResultExt};
use itertools::Itertools;

use axelar_wasm_std::flagset::FlagSet;
use router_api::error::Error;
use router_api::{ChainEndpoint, ChainName, Gateway, GatewayDirection, Message};

use crate::events::{
    ChainFrozen, ChainRegistered, ChainUnfrozen, GatewayInfo, GatewayUpgraded, MessageRouted,
};
use crate::state::{chain_endpoints, Store, CONFIG};

use super::Contract;

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

pub fn freeze_chain(
    deps: DepsMut,
    chain: ChainName,
    direction: GatewayDirection,
) -> Result<Response, Error> {
    chain_endpoints().update(deps.storage, chain.clone(), |chain| match chain {
        None => Err(Error::ChainNotFound),
        Some(mut chain) => {
            *chain.frozen_status |= direction;
            Ok(chain)
        }
    })?;
    Ok(Response::new().add_event(
        ChainFrozen {
            name: chain,
            direction,
        }
        .into(),
    ))
}

#[allow(clippy::arithmetic_side_effects)] // flagset operations don't cause under/overflows
pub fn unfreeze_chain(
    deps: DepsMut,
    chain: ChainName,
    direction: GatewayDirection,
) -> Result<Response, Error> {
    chain_endpoints().update(deps.storage, chain.clone(), |chain| match chain {
        None => Err(Error::ChainNotFound),
        Some(mut chain) => {
            *chain.frozen_status -= direction;
            Ok(chain)
        }
    })?;
    Ok(Response::new().add_event(
        ChainUnfrozen {
            name: chain,
            direction,
        }
        .into(),
    ))
}

pub fn require_admin(deps: &DepsMut, info: MessageInfo) -> Result<(), Error> {
    let config = CONFIG.load(deps.storage)?;
    if config.admin != info.sender {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

pub fn require_governance(deps: &DepsMut, info: MessageInfo) -> Result<(), Error> {
    let config = CONFIG.load(deps.storage)?;
    if config.governance != info.sender {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

fn verify_msg_ids(
    msgs: &[Message],
    expected_format: &MessageIdFormat,
) -> Result<(), error_stack::Report<Error>> {
    msgs.iter()
        .try_for_each(|msg| msg_id::verify_msg_id(&msg.cc_id.id, expected_format))
        .change_context(Error::InvalidMessageId)
}

impl<S> Contract<S>
where
    S: Store,
{
    fn validate_msgs(
        &self,
        sender: &Addr,
        msgs: Vec<Message>,
    ) -> error_stack::Result<Vec<Message>, Error> {
        // If sender is the nexus gateway, we cannot validate the source chain
        // because the source chain is registered in the core nexus module.
        // All messages received from the nexus gateway must adhere to the
        // HexTxHashAndEventIndex message ID format.
        if sender == self.config.nexus_gateway {
            verify_msg_ids(&msgs, &MessageIdFormat::HexTxHashAndEventIndex)?;
            return Ok(msgs);
        }

        let source_chain = self
            .store
            .load_chain_by_gateway(sender)?
            .ok_or(Error::GatewayNotRegistered)?;
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
        self,
        sender: Addr,
        msgs: Vec<Message>,
    ) -> error_stack::Result<Response, Error> {
        let msgs = self.validate_msgs(&sender, msgs)?;

        let wasm_msgs = msgs
            .iter()
            .group_by(|msg| msg.destination_chain.to_owned())
            .into_iter()
            .map(|(destination_chain, msgs)| {
                let gateway = match self.store.load_chain_by_chain_name(&destination_chain)? {
                    Some(destination_chain) if destination_chain.outgoing_frozen() => {
                        return Err(report!(Error::ChainFrozen {
                            chain: destination_chain.name,
                        }));
                    }
                    Some(destination_chain) => destination_chain.gateway.address,
                    // messages with unknown destination chains are routed to
                    // the nexus gateway if the sender is not the nexus gateway
                    // itself
                    None if sender != self.config.nexus_gateway => {
                        self.config.nexus_gateway.clone()
                    }
                    _ => return Err(report!(Error::ChainNotFound)),
                };

                Ok(WasmMsg::Execute {
                    contract_addr: gateway.to_string(),
                    msg: to_binary(&gateway_api::msg::ExecuteMsg::RouteMessages(
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
}

#[cfg(test)]
mod test {
    use axelar_wasm_std::msg_id::tx_hash_event_index::HexTxHashAndEventIndex;
    use cosmwasm_std::Addr;
    use mockall::predicate;
    use rand::{Rng, RngCore};

    use axelar_wasm_std::flagset::FlagSet;
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::Storage;
    use router_api::error::Error;
    use router_api::{ChainEndpoint, ChainName, CrossChainId, Gateway, GatewayDirection, Message};

    use crate::events::{ChainFrozen, ChainUnfrozen};
    use crate::state::chain_endpoints;
    use crate::{
        contract::Contract,
        state::{Config, MockStore},
    };

    use super::{freeze_chain, unfreeze_chain};

    fn rand_message(source_chain: ChainName, destination_chain: ChainName) -> Message {
        let mut bytes = [0; 32];
        rand::thread_rng().fill_bytes(&mut bytes);

        let id = HexTxHashAndEventIndex {
            tx_hash: bytes,
            event_index: rand::thread_rng().gen::<u32>(),
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
        let config = Config {
            admin: Addr::unchecked("admin"),
            governance: Addr::unchecked("governance"),
            nexus_gateway: Addr::unchecked("nexus_gateway"),
        };
        let sender = Addr::unchecked("sender");
        let source_chain: ChainName = "ethereum".parse().unwrap();
        let destination_chain = "bitcoin".parse().unwrap();

        let mut store = MockStore::new();
        store
            .expect_load_config()
            .returning(move || Ok(config.clone()));
        store
            .expect_load_chain_by_gateway()
            .once()
            .with(predicate::eq(sender.clone()))
            .return_once(|_| Ok(None));

        let contract = Contract::new(store);

        assert!(contract
            .route_messages(sender, vec![rand_message(source_chain, destination_chain)])
            .is_err_and(move |err| {
                matches!(err.current_context(), Error::GatewayNotRegistered)
            }));
    }

    #[test]
    fn route_messages_with_frozen_source_chain() {
        let config = Config {
            admin: Addr::unchecked("admin"),
            governance: Addr::unchecked("governance"),
            nexus_gateway: Addr::unchecked("nexus_gateway"),
        };
        let sender = Addr::unchecked("sender");
        let source_chain: ChainName = "ethereum".parse().unwrap();
        let destination_chain = "bitcoin".parse().unwrap();

        let mut store = MockStore::new();
        store
            .expect_load_config()
            .returning(move || Ok(config.clone()));
        let chain_endpoint = ChainEndpoint {
            name: source_chain.clone(),
            gateway: Gateway {
                address: sender.clone(),
            },
            frozen_status: FlagSet::from(GatewayDirection::Incoming),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        };
        store
            .expect_load_chain_by_gateway()
            .once()
            .with(predicate::eq(sender.clone()))
            .return_once(|_| Ok(Some(chain_endpoint)));

        let contract = Contract::new(store);

        assert!(contract
            .route_messages(sender, vec![rand_message(source_chain.clone(), destination_chain)])
            .is_err_and(move |err| {
                matches!(err.current_context(), Error::ChainFrozen { chain } if *chain == source_chain)
            }));
    }

    #[test]
    fn route_messages_with_wrong_source_chain() {
        let config = Config {
            admin: Addr::unchecked("admin"),
            governance: Addr::unchecked("governance"),
            nexus_gateway: Addr::unchecked("nexus_gateway"),
        };
        let sender = Addr::unchecked("sender");
        let source_chain: ChainName = "ethereum".parse().unwrap();
        let destination_chain = "bitcoin".parse().unwrap();

        let mut store = MockStore::new();
        store
            .expect_load_config()
            .returning(move || Ok(config.clone()));
        let chain_endpoint = ChainEndpoint {
            name: source_chain.clone(),
            gateway: Gateway {
                address: sender.clone(),
            },
            frozen_status: FlagSet::from(GatewayDirection::None),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        };
        store
            .expect_load_chain_by_gateway()
            .once()
            .with(predicate::eq(sender.clone()))
            .return_once(|_| Ok(Some(chain_endpoint)));

        let contract = Contract::new(store);

        assert!(contract
            .route_messages(
                sender,
                vec![rand_message("polygon".parse().unwrap(), destination_chain)]
            )
            .is_err_and(|err| { matches!(err.current_context(), Error::WrongSourceChain) }));
    }

    #[test]
    fn route_messages_with_frozen_destination_chain() {
        let config = Config {
            admin: Addr::unchecked("admin"),
            governance: Addr::unchecked("governance"),
            nexus_gateway: Addr::unchecked("nexus_gateway"),
        };
        let sender = Addr::unchecked("sender");
        let source_chain: ChainName = "ethereum".parse().unwrap();
        let destination_chain: ChainName = "bitcoin".parse().unwrap();

        let mut store = MockStore::new();
        store
            .expect_load_config()
            .returning(move || Ok(config.clone()));
        let source_chain_endpoint = ChainEndpoint {
            name: source_chain.clone(),
            gateway: Gateway {
                address: sender.clone(),
            },
            frozen_status: FlagSet::from(GatewayDirection::None),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        };
        store
            .expect_load_chain_by_gateway()
            .once()
            .with(predicate::eq(sender.clone()))
            .return_once(|_| Ok(Some(source_chain_endpoint)));
        let destination_chain_endpoint = ChainEndpoint {
            name: destination_chain.clone(),
            gateway: Gateway {
                address: sender.clone(),
            },
            frozen_status: FlagSet::from(GatewayDirection::Bidirectional),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        };
        store
            .expect_load_chain_by_chain_name()
            .once()
            .with(predicate::eq(destination_chain.clone()))
            .return_once(|_| Ok(Some(destination_chain_endpoint)));

        let contract = Contract::new(store);

        assert!(contract
            .route_messages(sender, vec![rand_message(source_chain, destination_chain.clone())])
            .is_err_and(move |err| {
                matches!(err.current_context(), Error::ChainFrozen { chain } if *chain == destination_chain)
            }));
    }

    #[test]
    fn route_messages_from_non_nexus_with_invalid_message_id() {
        let config = Config {
            admin: Addr::unchecked("admin"),
            governance: Addr::unchecked("governance"),
            nexus_gateway: Addr::unchecked("nexus_gateway"),
        };
        let sender = Addr::unchecked("sender");
        let source_chain: ChainName = "ethereum".parse().unwrap();
        let destination_chain: ChainName = "bitcoin".parse().unwrap();

        let mut store = MockStore::new();
        store
            .expect_load_config()
            .returning(move || Ok(config.clone()));
        let source_chain_endpoint = ChainEndpoint {
            name: source_chain.clone(),
            gateway: Gateway {
                address: sender.clone(),
            },
            frozen_status: FlagSet::from(GatewayDirection::None),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        };
        store
            .expect_load_chain_by_gateway()
            .once()
            .with(predicate::eq(sender.clone()))
            .return_once(|_| Ok(Some(source_chain_endpoint)));

        let contract = Contract::new(store);

        let mut msg = rand_message(source_chain, destination_chain.clone());
        msg.cc_id.id = "foobar".try_into().unwrap();
        assert!(contract
            .route_messages(sender, vec![msg])
            .is_err_and(move |err| { matches!(err.current_context(), Error::InvalidMessageId) }));
    }

    #[test]
    fn route_messages_from_nexus_with_invalid_message_id() {
        let config = Config {
            admin: Addr::unchecked("admin"),
            governance: Addr::unchecked("governance"),
            nexus_gateway: Addr::unchecked("nexus_gateway"),
        };
        let sender = config.nexus_gateway.clone();
        let source_chain: ChainName = "ethereum".parse().unwrap();
        let destination_chain: ChainName = "bitcoin".parse().unwrap();

        let mut store = MockStore::new();
        store
            .expect_load_config()
            .returning(move || Ok(config.clone()));

        let contract = Contract::new(store);

        let mut msg = rand_message(source_chain, destination_chain.clone());
        msg.cc_id.id = "foobar".try_into().unwrap();
        assert!(contract
            .route_messages(sender, vec![msg])
            .is_err_and(move |err| { matches!(err.current_context(), Error::InvalidMessageId) }));
    }

    #[test]
    fn route_messages_from_non_nexus_with_incorrect_message_id_format() {
        let config = Config {
            admin: Addr::unchecked("admin"),
            governance: Addr::unchecked("governance"),
            nexus_gateway: Addr::unchecked("nexus_gateway"),
        };
        let sender = Addr::unchecked("sender");
        let source_chain: ChainName = "ethereum".parse().unwrap();
        let destination_chain: ChainName = "bitcoin".parse().unwrap();

        let mut store = MockStore::new();
        store
            .expect_load_config()
            .returning(move || Ok(config.clone()));
        let source_chain_endpoint = ChainEndpoint {
            name: source_chain.clone(),
            gateway: Gateway {
                address: sender.clone(),
            },
            frozen_status: FlagSet::from(GatewayDirection::None),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::Base58TxDigestAndEventIndex,
        };
        store
            .expect_load_chain_by_gateway()
            .once()
            .with(predicate::eq(sender.clone()))
            .return_once(|_| Ok(Some(source_chain_endpoint)));

        let contract = Contract::new(store);

        let mut msg = rand_message(source_chain, destination_chain.clone());
        msg.cc_id.id = HexTxHashAndEventIndex {
            tx_hash: [0; 32],
            event_index: 0,
        }
        .to_string()
        .try_into()
        .unwrap();
        assert!(contract
            .route_messages(sender, vec![msg])
            .is_err_and(move |err| { matches!(err.current_context(), Error::InvalidMessageId) }));
    }

    #[test]
    fn route_messages_from_non_nexus_to_non_nexus() {
        let config = Config {
            admin: Addr::unchecked("admin"),
            governance: Addr::unchecked("governance"),
            nexus_gateway: Addr::unchecked("nexus_gateway"),
        };
        let sender = Addr::unchecked("sender");
        let source_chain: ChainName = "ethereum".parse().unwrap();
        let destination_chain_1: ChainName = "bitcoin".parse().unwrap();
        let destination_chain_2: ChainName = "polygon".parse().unwrap();

        let mut store = MockStore::new();
        store
            .expect_load_config()
            .returning(move || Ok(config.clone()));
        let source_chain_endpoint = ChainEndpoint {
            name: source_chain.clone(),
            gateway: Gateway {
                address: sender.clone(),
            },
            frozen_status: FlagSet::from(GatewayDirection::None),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        };
        store
            .expect_load_chain_by_gateway()
            .once()
            .with(predicate::eq(sender.clone()))
            .return_once(|_| Ok(Some(source_chain_endpoint)));
        let destination_chain_endpoint_1 = ChainEndpoint {
            name: destination_chain_1.clone(),
            gateway: Gateway {
                address: sender.clone(),
            },
            frozen_status: FlagSet::from(GatewayDirection::None),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        };
        store
            .expect_load_chain_by_chain_name()
            .once()
            .with(predicate::eq(destination_chain_1.clone()))
            .return_once(|_| Ok(Some(destination_chain_endpoint_1)));
        let destination_chain_endpoint_2 = ChainEndpoint {
            name: destination_chain_2.clone(),
            gateway: Gateway {
                address: sender.clone(),
            },
            frozen_status: FlagSet::from(GatewayDirection::None),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        };
        store
            .expect_load_chain_by_chain_name()
            .once()
            .with(predicate::eq(destination_chain_2.clone()))
            .return_once(|_| Ok(Some(destination_chain_endpoint_2)));

        let contract = Contract::new(store);

        assert!(contract
            .route_messages(
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

        let mut store = MockStore::new();
        store
            .expect_load_config()
            .returning(move || Ok(config.clone()));
        let destination_chain_endpoint_1 = ChainEndpoint {
            name: destination_chain_1.clone(),
            gateway: Gateway {
                address: sender.clone(),
            },
            frozen_status: FlagSet::from(GatewayDirection::None),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        };
        store
            .expect_load_chain_by_chain_name()
            .once()
            .with(predicate::eq(destination_chain_1.clone()))
            .return_once(|_| Ok(Some(destination_chain_endpoint_1)));
        let destination_chain_endpoint_2 = ChainEndpoint {
            name: destination_chain_2.clone(),
            gateway: Gateway {
                address: sender.clone(),
            },
            frozen_status: FlagSet::from(GatewayDirection::None),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        };
        store
            .expect_load_chain_by_chain_name()
            .once()
            .with(predicate::eq(destination_chain_2.clone()))
            .return_once(|_| Ok(Some(destination_chain_endpoint_2)));

        let contract = Contract::new(store);

        assert!(contract
            .route_messages(
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
        let config = Config {
            admin: Addr::unchecked("admin"),
            governance: Addr::unchecked("governance"),
            nexus_gateway: Addr::unchecked("nexus_gateway"),
        };
        let sender = config.nexus_gateway.clone();
        let source_chain: ChainName = "ethereum".parse().unwrap();
        let destination_chain: ChainName = "bitcoin".parse().unwrap();

        let mut store = MockStore::new();
        store
            .expect_load_config()
            .returning(move || Ok(config.clone()));
        store
            .expect_load_chain_by_chain_name()
            .once()
            .with(predicate::eq(destination_chain.clone()))
            .return_once(|_| Ok(None));

        let contract = Contract::new(store);

        assert!(contract
            .route_messages(
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
        let config = Config {
            admin: Addr::unchecked("admin"),
            governance: Addr::unchecked("governance"),
            nexus_gateway: Addr::unchecked("nexus_gateway"),
        };
        let sender = Addr::unchecked("sender");
        let source_chain: ChainName = "ethereum".parse().unwrap();
        let destination_chain: ChainName = "bitcoin".parse().unwrap();

        let mut store = MockStore::new();
        store
            .expect_load_config()
            .returning(move || Ok(config.clone()));
        let source_chain_endpoint = ChainEndpoint {
            name: source_chain.clone(),
            gateway: Gateway {
                address: sender.clone(),
            },
            frozen_status: FlagSet::from(GatewayDirection::None),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        };
        store
            .expect_load_chain_by_gateway()
            .once()
            .with(predicate::eq(sender.clone()))
            .return_once(|_| Ok(Some(source_chain_endpoint)));
        store
            .expect_load_chain_by_chain_name()
            .once()
            .with(predicate::eq(destination_chain.clone()))
            .return_once(|_| Ok(None));

        let contract = Contract::new(store);

        assert!(contract
            .route_messages(
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
        freeze_chain(deps.as_mut(), chain.clone(), GatewayDirection::Incoming).unwrap();
        freeze_chain(deps.as_mut(), chain.clone(), GatewayDirection::Incoming).unwrap();

        assert_chain_endpoint_frozen_status(
            deps.as_mut().storage,
            chain.clone(),
            FlagSet::from(GatewayDirection::Incoming),
        );

        freeze_chain(
            deps.as_mut(),
            chain.clone(),
            GatewayDirection::Bidirectional,
        )
        .unwrap();
        freeze_chain(
            deps.as_mut(),
            chain.clone(),
            GatewayDirection::Bidirectional,
        )
        .unwrap();

        assert_chain_endpoint_frozen_status(
            deps.as_mut().storage,
            chain.clone(),
            FlagSet::from(GatewayDirection::Bidirectional),
        );

        // unfreezing twice produces same result
        unfreeze_chain(deps.as_mut(), chain.clone(), GatewayDirection::Outgoing).unwrap();
        unfreeze_chain(deps.as_mut(), chain.clone(), GatewayDirection::Outgoing).unwrap();

        assert_chain_endpoint_frozen_status(
            deps.as_mut().storage,
            chain.clone(),
            FlagSet::from(GatewayDirection::Incoming),
        );

        unfreeze_chain(
            deps.as_mut(),
            chain.clone(),
            GatewayDirection::Bidirectional,
        )
        .unwrap();
        unfreeze_chain(
            deps.as_mut(),
            chain.clone(),
            GatewayDirection::Bidirectional,
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

        let res = freeze_chain(deps.as_mut(), chain.clone(), GatewayDirection::Incoming).unwrap();

        assert_eq!(res.events.len(), 1);
        assert!(res.events.contains(
            &ChainFrozen {
                name: chain.clone(),
                direction: GatewayDirection::Incoming,
            }
            .into()
        ));

        let res = unfreeze_chain(deps.as_mut(), chain.clone(), GatewayDirection::Incoming).unwrap();

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
