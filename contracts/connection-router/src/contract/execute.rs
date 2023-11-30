use std::vec;

use cosmwasm_std::{to_binary, Addr, DepsMut, MessageInfo, Response, StdResult, WasmMsg};
use error_stack::report;
use itertools::Itertools;

use axelar_wasm_std::flagset::FlagSet;

use crate::events::{ChainFrozen, ChainRegistered, GatewayInfo, GatewayUpgraded, MessageRouted};
use crate::msg::ExecuteMsg;
use crate::state::{
    chain_endpoints, ChainEndpoint, ChainName, Gateway, GatewayDirection, Message, Store, CONFIG,
};
use crate::ContractError;

use super::Contract;

pub fn register_chain(
    deps: DepsMut,
    name: ChainName,
    gateway: Addr,
) -> Result<Response, ContractError> {
    if find_chain_for_gateway(&deps, &gateway)?.is_some() {
        return Err(ContractError::GatewayAlreadyRegistered);
    }
    chain_endpoints().update(deps.storage, name.clone(), |chain| match chain {
        Some(_) => Err(ContractError::ChainAlreadyExists),
        None => Ok(ChainEndpoint {
            name: name.clone(),
            gateway: Gateway {
                address: gateway.clone(),
            },
            frozen_status: FlagSet::from(GatewayDirection::None),
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
) -> Result<Response, ContractError> {
    if find_chain_for_gateway(&deps, &contract_address)?.is_some() {
        return Err(ContractError::GatewayAlreadyRegistered);
    }
    chain_endpoints().update(deps.storage, chain.clone(), |chain| match chain {
        None => Err(ContractError::ChainNotFound),
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
) -> Result<Response, ContractError> {
    chain_endpoints().update(deps.storage, chain.clone(), |chain| match chain {
        None => Err(ContractError::ChainNotFound),
        Some(mut chain) => {
            *chain.frozen_status |= direction;
            Ok(chain)
        }
    })?;
    Ok(Response::new().add_event(ChainFrozen { name: chain }.into()))
}

pub fn unfreeze_chain(
    deps: DepsMut,
    chain: ChainName,
    direction: GatewayDirection,
) -> Result<Response, ContractError> {
    chain_endpoints().update(deps.storage, chain.clone(), |chain| match chain {
        None => Err(ContractError::ChainNotFound),
        Some(mut chain) => {
            *chain.frozen_status -= direction;
            Ok(chain)
        }
    })?;
    Ok(Response::new().add_event(ChainFrozen { name: chain }.into()))
}

pub fn require_admin(deps: &DepsMut, info: MessageInfo) -> Result<(), ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if config.admin != info.sender {
        return Err(ContractError::Unauthorized);
    }
    Ok(())
}

pub fn require_governance(deps: &DepsMut, info: MessageInfo) -> Result<(), ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if config.governance != info.sender {
        return Err(ContractError::Unauthorized);
    }
    Ok(())
}

impl<S> Contract<S>
where
    S: Store,
{
    fn validate_msgs(
        &self,
        sender: &Addr,
        msgs: Vec<Message>,
    ) -> error_stack::Result<Vec<Message>, ContractError> {
        // if sender is the nexus gateway, we cannot validate the source chain
        // because the source chain is registered in the core nexus module
        if sender == self.config.nexus_gateway {
            return Ok(msgs);
        }

        let source_chain = self
            .store
            .load_chain_by_gateway(sender)?
            .ok_or(ContractError::GatewayNotRegistered)?;
        if source_chain.incoming_frozen() {
            return Err(report!(ContractError::ChainFrozen {
                chain: source_chain.name,
            }));
        }

        if msgs.iter().any(|msg| msg.cc_id.chain != source_chain.name) {
            return Err(report!(ContractError::WrongSourceChain));
        }

        Ok(msgs)
    }

    pub fn route_messages(
        self,
        sender: Addr,
        msgs: Vec<Message>,
    ) -> error_stack::Result<Response, ContractError> {
        let msgs = self.validate_msgs(&sender, msgs)?;

        let wasm_msgs = msgs
            .iter()
            .group_by(|msg| msg.destination_chain.to_owned())
            .into_iter()
            .map(|(destination_chain, msgs)| {
                let gateway = match self.store.load_chain_by_chain_name(&destination_chain)? {
                    Some(destination_chain) if destination_chain.outgoing_frozen() => {
                        return Err(report!(ContractError::ChainFrozen {
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
                    _ => return Err(report!(ContractError::ChainNotFound)),
                };

                Ok(WasmMsg::Execute {
                    contract_addr: gateway.to_string(),
                    // TODO: this happens to work because the router and the gateways have the same definition of RouteMessages
                    msg: to_binary(&ExecuteMsg::RouteMessages(msgs.cloned().collect()))
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
    use axelar_wasm_std::flagset::FlagSet;
    use cosmwasm_std::Addr;
    use mockall::predicate;
    use rand::{Rng, RngCore};

    use crate::{
        contract::Contract,
        state::{
            ChainEndpoint, ChainName, Config, CrossChainId, Gateway, GatewayDirection, MockStore,
            ID_SEPARATOR,
        },
        ContractError, Message,
    };

    fn rand_message(source_chain: ChainName, destination_chain: ChainName) -> Message {
        let mut bytes = [0; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let tx_id = hex::encode(&bytes);

        let mut bytes = [0; 20];
        rand::thread_rng().fill_bytes(&mut bytes);
        let source_address = format!("0x{}", hex::encode(&bytes)).try_into().unwrap();

        let mut bytes = [0; 20];
        rand::thread_rng().fill_bytes(&mut bytes);
        let destination_address = format!("0x{}", hex::encode(&bytes)).try_into().unwrap();

        let mut payload_hash = [0; 32];
        rand::thread_rng().fill_bytes(&mut payload_hash);

        Message {
            cc_id: CrossChainId {
                chain: source_chain,
                id: format!(
                    "{}{}{}",
                    tx_id,
                    ID_SEPARATOR,
                    rand::thread_rng().gen::<u32>()
                )
                .try_into()
                .unwrap(),
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
                matches!(err.current_context(), ContractError::GatewayNotRegistered)
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
                matches!(err.current_context(), ContractError::ChainFrozen { chain } if *chain == source_chain)
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
            .is_err_and(|err| {
                matches!(err.current_context(), ContractError::WrongSourceChain)
            }));
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
                matches!(err.current_context(), ContractError::ChainFrozen { chain } if *chain == destination_chain)
            }));
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
            .is_err_and(|err| { matches!(err.current_context(), ContractError::ChainNotFound) }));
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
}
