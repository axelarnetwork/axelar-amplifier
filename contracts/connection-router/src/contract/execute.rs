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

impl<S> Contract<S>
where
    S: Store,
{
    pub fn route_messages(
        self,
        sender: Addr,
        msgs: Vec<Message>,
    ) -> error_stack::Result<Response, ContractError> {
        let source_chain = self
            .store
            .load_chain_by_gateway(&sender)?
            .ok_or(ContractError::GatewayNotRegistered)?;
        if source_chain.incoming_frozen() {
            return Err(report!(ContractError::ChainFrozen {
                chain: source_chain.name,
            }));
        }

        if msgs.iter().any(|msg| msg.cc_id.chain != source_chain.name) {
            return Err(report!(ContractError::WrongSourceChain));
        }

        let mut wasm_msgs = vec![];

        for (destination_chain, msgs) in &msgs.iter().group_by(|msg| msg.destination_chain.clone())
        {
            let destination_chain = self
                .store
                .load_chain_by_chain_name(&destination_chain)?
                .ok_or(ContractError::ChainNotFound)?;
            if destination_chain.outgoing_frozen() {
                return Err(report!(ContractError::ChainFrozen {
                    chain: destination_chain.name,
                }));
            }

            wasm_msgs.push(WasmMsg::Execute {
                contract_addr: destination_chain.gateway.address.to_string(),
                msg: to_binary(&ExecuteMsg::RouteMessages(msgs.cloned().collect()))
                    .expect("must serialize message"),
                funds: vec![],
            });
        }

        Ok(Response::new()
            .add_messages(wasm_msgs)
            .add_events(msgs.into_iter().map(|msg| MessageRouted { msg }.into())))
    }
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
