#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};

use crate::error::ContractError;
use crate::events::{ChainRegistered, RouterInstantiated};
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{chain_endpoints, Config, CONFIG};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let admin = deps.api.addr_validate(&msg.admin_address)?;
    let governance = deps.api.addr_validate(&msg.governance_address)?;
    CONFIG.save(
        deps.storage,
        &Config {
            admin: admin.clone(),
            governance: governance.clone(),
        },
    )?;
    Ok(Response::new().add_event(RouterInstantiated { admin, governance }.into()))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    match msg {
        ExecuteMsg::RegisterChain {
            chain,
            gateway_address,
        } => {
            execute::require_governance(&deps, info)?;
            let gateway_address = deps.api.addr_validate(&gateway_address)?;
            execute::register_chain(deps, chain.parse()?, gateway_address)
        }
        ExecuteMsg::UpgradeGateway {
            chain,
            contract_address,
        } => {
            execute::require_governance(&deps, info)?;
            let contract_address = deps.api.addr_validate(&contract_address)?;
            execute::upgrade_gateway(deps, chain.parse()?, contract_address)
        }
        ExecuteMsg::FreezeChain { chain, direction } => {
            execute::require_admin(&deps, info)?;
            execute::freeze_chain(deps, chain.parse()?, direction)
        }
        ExecuteMsg::UnfreezeChain { chain, direction } => {
            execute::require_admin(&deps, info)?;
            execute::unfreeze_chain(deps, chain.parse()?, direction)
        }
        ExecuteMsg::RouteMessages(msgs) => execute::route_message(deps, info, msgs),
    }
    .map_err(axelar_wasm_std::ContractError::from)
}

pub mod execute {
    use std::vec;

    use cosmwasm_std::{Addr, WasmMsg};
    use itertools::Itertools;

    use axelar_wasm_std::flagset::FlagSet;

    use crate::events::{ChainFrozen, GatewayInfo, GatewayUpgraded, MessageRouted};
    use crate::state::{ChainEndpoint, ChainName, Gateway, GatewayDirection, Message};

    use super::*;

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

    fn incoming_frozen(direction: &FlagSet<GatewayDirection>) -> bool {
        direction.contains(GatewayDirection::Incoming)
    }

    fn outgoing_frozen(direction: &FlagSet<GatewayDirection>) -> bool {
        direction.contains(GatewayDirection::Outgoing)
    }

    pub fn route_message(
        deps: DepsMut,
        info: MessageInfo,
        msgs: Vec<Message>,
    ) -> Result<Response, ContractError> {
        let source_chain = find_chain_for_gateway(&deps, &info.sender)?
            .ok_or(ContractError::GatewayNotRegistered)?;
        if incoming_frozen(&source_chain.frozen_status) {
            return Err(ContractError::ChainFrozen {
                chain: source_chain.name,
            });
        }

        if msgs.iter().any(|msg| msg.cc_id.chain != source_chain.name) {
            return Err(ContractError::WrongSourceChain);
        }

        let mut wasm_msgs = vec![];

        for (destination_chain, msgs) in &msgs.iter().group_by(|msg| msg.destination_chain.clone())
        {
            let destination_chain = chain_endpoints()
                .may_load(deps.storage, destination_chain)?
                .ok_or(ContractError::ChainNotFound)?;

            if outgoing_frozen(&destination_chain.frozen_status) {
                return Err(ContractError::ChainFrozen {
                    chain: destination_chain.name,
                });
            }

            wasm_msgs.push(WasmMsg::Execute {
                contract_addr: destination_chain.gateway.address.to_string(),
                msg: to_binary(&ExecuteMsg::RouteMessages(msgs.cloned().collect()))?,
                funds: vec![],
            });
        }

        Ok(Response::new()
            .add_messages(wasm_msgs)
            .add_events(msgs.into_iter().map(|msg| MessageRouted { msg }.into())))
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
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, _msg: QueryMsg) -> StdResult<Binary> {
    todo!()
}

pub mod query {}
