use std::str::FromStr;

#[cfg(not(feature = "library"))]
use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, Event, HexBinary, MessageInfo, Order,
    Response, StdResult,
};
use cw_storage_plus::VecDeque;

use crate::error::ContractError;
use crate::events::{DomainRegistered, RouterInstantiated};
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{domains, Config, Domain, DomainName, Message, CONFIG, MESSAGES};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let admin = deps.api.addr_validate(&msg.admin_address)?;
    CONFIG.save(
        deps.storage,
        &Config {
            admin: admin.clone(),
        },
    )?;
    Ok(Response::new().add_event(RouterInstantiated { admin }.into()))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::RegisterDomain {
            domain,
            incoming_gateway_address,
            outgoing_gateway_address,
        } => {
            let incoming_validated = deps.api.addr_validate(&incoming_gateway_address)?;
            let outgoing_validated = deps.api.addr_validate(&outgoing_gateway_address)?;
            execute::require_admin(&deps, info)?;
            execute::register_domain(
                deps,
                DomainName::from_str(&domain)?,
                incoming_validated,
                outgoing_validated,
            )
        }
        ExecuteMsg::UpgradeIncomingGateway {
            domain,
            contract_address,
        } => {
            execute::require_admin(&deps, info)?;
            let addr_validated = deps.api.addr_validate(&contract_address)?;
            execute::upgrade_incoming_gateway(deps, DomainName::from_str(&domain)?, addr_validated)
        }
        ExecuteMsg::UpgradeOutgoingGateway {
            domain,
            contract_address,
        } => {
            execute::require_admin(&deps, info)?;
            let addr_validated = deps.api.addr_validate(&contract_address)?;
            execute::upgrade_outgoing_gateway(deps, DomainName::from_str(&domain)?, addr_validated)
        }
        ExecuteMsg::FreezeIncomingGateway { domain } => {
            execute::require_admin(&deps, info)?;
            execute::freeze_incoming_gateway(deps, DomainName::from_str(&domain)?)
        }
        ExecuteMsg::FreezeOutgoingGateway { domain } => {
            execute::require_admin(&deps, info)?;
            execute::freeze_outgoing_gateway(deps, DomainName::from_str(&domain)?)
        }
        ExecuteMsg::FreezeDomain { domain } => {
            execute::require_admin(&deps, info)?;
            execute::freeze_domain(deps, DomainName::from_str(&domain)?)
        }
        ExecuteMsg::UnfreezeDomain { domain } => {
            execute::require_admin(&deps, info)?;
            execute::unfreeze_domain(deps, DomainName::from_str(&domain)?)
        }
        ExecuteMsg::UnfreezeIncomingGateway { domain } => {
            execute::require_admin(&deps, info)?;
            execute::unfreeze_incoming_gateway(deps, DomainName::from_str(&domain)?)
        }
        ExecuteMsg::UnfreezeOutgoingGateway { domain } => {
            execute::require_admin(&deps, info)?;
            execute::unfreeze_outgoing_gateway(deps, DomainName::from_str(&domain)?)
        }
        ExecuteMsg::RouteMessage {
            id,
            destination_domain,
            destination_address,
            source_address,
            payload_hash,
        } => execute::route_message(
            deps,
            info,
            id,
            DomainName::from_str(&destination_domain)?,
            destination_address,
            source_address,
            payload_hash,
        ),
        ExecuteMsg::ConsumeMessages { count } => execute::consume_messages(deps, info, count),
    }
}

pub mod execute {

    use cosmwasm_std::{Addr, StdError};

    use crate::{
        events::{
            DomainFrozen, DomainUnfrozen, GatewayFrozen, GatewayInfo, GatewayUnfrozen,
            GatewayUpgraded, MessageRouted, MessagesConsumed,
        },
        state::Gateway,
    };

    use super::*;

    pub fn register_domain(
        deps: DepsMut,
        name: DomainName,
        incoming_gateway: Addr,
        outgoing_gateway: Addr,
    ) -> Result<Response, ContractError> {
        if find_domain_for_incoming_gateway(&deps, &incoming_gateway)?.is_some() {
            return Err(ContractError::GatewayAlreadyRegistered {});
        }
        if find_domain_for_outgoing_gateway(&deps, &outgoing_gateway)?.is_some() {
            return Err(ContractError::GatewayAlreadyRegistered {});
        }
        domains().update(deps.storage, name.clone(), |e| match e {
            None => Ok(Domain {
                incoming_gateway: Gateway {
                    address: incoming_gateway.clone(),
                    is_frozen: false,
                },
                outgoing_gateway: Gateway {
                    address: outgoing_gateway.clone(),
                    is_frozen: false,
                },
                is_frozen: false,
            }),
            Some(_) => Err(ContractError::DomainAlreadyExists {}),
        })?;
        Ok(Response::new().add_event(
            DomainRegistered {
                name,
                incoming_gateway,
                outgoing_gateway,
            }
            .into(),
        ))
    }

    pub fn find_domain_for_incoming_gateway(
        deps: &DepsMut,
        contract_address: &Addr,
    ) -> StdResult<Option<(DomainName, Domain)>> {
        find_domain_for_gateway(deps, contract_address, true)
    }

    pub fn find_domain_for_outgoing_gateway(
        deps: &DepsMut,
        contract_address: &Addr,
    ) -> StdResult<Option<(DomainName, Domain)>> {
        find_domain_for_gateway(deps, contract_address, false)
    }

    pub fn find_domain_for_gateway(
        deps: &DepsMut,
        contract_address: &Addr,
        is_incoming: bool,
    ) -> StdResult<Option<(DomainName, Domain)>> {
        let multi_index = if is_incoming {
            domains().idx.incoming_gateway
        } else {
            domains().idx.outgoing_gateway
        };
        let matching_domains = &multi_index
            .prefix(contract_address.clone())
            .range(deps.storage, None, None, Order::Ascending)
            .collect::<Result<Vec<(String, Domain)>, _>>()?;
        match &matching_domains[..] {
            [] => Ok(None),
            [(name, domain)] => Ok(Some((DomainName::from_str(name).unwrap(), domain.clone()))),
            _ => Err(StdError::GenericErr {
                msg: String::from("More than one domain for gateway address. Should never happen"),
            }),
        }
    }

    pub fn upgrade_incoming_gateway(
        deps: DepsMut,
        domain: DomainName,
        contract_address: Addr,
    ) -> Result<Response, ContractError> {
        if find_domain_for_incoming_gateway(&deps, &contract_address)?.is_some() {
            return Err(ContractError::GatewayAlreadyRegistered {});
        }
        domains().update(deps.storage, domain.clone(), |e| match e {
            None => Err(ContractError::DomainNotFound {}),
            Some(mut d) => {
                d.incoming_gateway.address = contract_address.clone();
                Ok(d)
            }
        })?;
        Ok(Response::new().add_event(
            GatewayUpgraded {
                gateway: GatewayInfo {
                    domain,
                    gateway_address: contract_address,
                    incoming: true,
                },
            }
            .into(),
        ))
    }

    pub fn upgrade_outgoing_gateway(
        deps: DepsMut,
        domain: DomainName,
        contract_address: Addr,
    ) -> Result<Response, ContractError> {
        if find_domain_for_outgoing_gateway(&deps, &contract_address)?.is_some() {
            return Err(ContractError::GatewayAlreadyRegistered {});
        }
        domains().update(deps.storage, domain.clone(), |e| match e {
            None => Err(ContractError::DomainNotFound {}),
            Some(mut d) => {
                d.outgoing_gateway.address = contract_address.clone();
                Ok(d)
            }
        })?;
        Ok(Response::new().add_event(
            GatewayUpgraded {
                gateway: GatewayInfo {
                    domain,
                    gateway_address: contract_address,
                    incoming: false,
                },
            }
            .into(),
        ))
    }

    pub fn freeze_domain(deps: DepsMut, domain: DomainName) -> Result<Response, ContractError> {
        domains().update(deps.storage, domain.clone(), |e| match e {
            None => Err(ContractError::DomainNotFound {}),
            Some(mut d) => {
                d.is_frozen = true;
                Ok(d)
            }
        })?;
        Ok(Response::new().add_event(DomainFrozen { name: domain }.into()))
    }
    pub fn freeze_incoming_gateway(
        deps: DepsMut,
        domain_name: DomainName,
    ) -> Result<Response, ContractError> {
        let domain_info = domains().update(deps.storage, domain_name.clone(), |d| match d {
            None => Err(ContractError::DomainNotFound {}),
            Some(mut d) => {
                d.incoming_gateway.is_frozen = true;
                Ok(d)
            }
        })?;
        Ok(Response::new().add_event(
            GatewayFrozen {
                gateway: GatewayInfo {
                    domain: domain_name,
                    gateway_address: domain_info.incoming_gateway.address,
                    incoming: true,
                },
            }
            .into(),
        ))
    }
    pub fn freeze_outgoing_gateway(
        deps: DepsMut,
        domain_name: DomainName,
    ) -> Result<Response, ContractError> {
        let domain_info = domains().update(deps.storage, domain_name.clone(), |d| match d {
            None => Err(ContractError::DomainNotFound {}),
            Some(mut d) => {
                d.outgoing_gateway.is_frozen = true;
                Ok(d)
            }
        })?;
        Ok(Response::new().add_event(
            GatewayFrozen {
                gateway: GatewayInfo {
                    domain: domain_name,
                    gateway_address: domain_info.outgoing_gateway.address,
                    incoming: false,
                },
            }
            .into(),
        ))
    }
    pub fn unfreeze_domain(
        deps: DepsMut,
        domain_name: DomainName,
    ) -> Result<Response, ContractError> {
        domains().update(deps.storage, domain_name.clone(), |d| match d {
            None => Err(ContractError::DomainNotFound {}),
            Some(mut d) => {
                d.is_frozen = false;
                Ok(d)
            }
        })?;
        Ok(Response::new().add_event(DomainUnfrozen { name: domain_name }.into()))
    }
    pub fn unfreeze_incoming_gateway(
        deps: DepsMut,
        domain_name: DomainName,
    ) -> Result<Response, ContractError> {
        let domain_info = domains().update(deps.storage, domain_name.clone(), |d| match d {
            None => Err(ContractError::DomainNotFound {}),
            Some(mut d) => {
                d.incoming_gateway.is_frozen = false;
                Ok(d)
            }
        })?;
        Ok(Response::new().add_event(
            GatewayUnfrozen {
                gateway: GatewayInfo {
                    domain: domain_name,
                    gateway_address: domain_info.incoming_gateway.address,
                    incoming: true,
                },
            }
            .into(),
        ))
    }

    pub fn unfreeze_outgoing_gateway(
        deps: DepsMut,
        domain_name: DomainName,
    ) -> Result<Response, ContractError> {
        let domain_info = domains().update(deps.storage, domain_name.clone(), |d| match d {
            None => Err(ContractError::DomainNotFound {}),
            Some(mut d) => {
                d.outgoing_gateway.is_frozen = false;
                Ok(d)
            }
        })?;
        Ok(Response::new().add_event(
            GatewayUnfrozen {
                gateway: GatewayInfo {
                    domain: domain_name,
                    gateway_address: domain_info.outgoing_gateway.address,
                    incoming: false,
                },
            }
            .into(),
        ))
    }

    pub fn route_message(
        deps: DepsMut,
        info: MessageInfo,
        id: String,
        destination_domain: DomainName,
        destination_address: String,
        source_address: String,
        payload_hash: HexBinary,
    ) -> Result<Response, ContractError> {
        let (source_domain, info) = find_domain_for_incoming_gateway(&deps, &info.sender)?
            .ok_or(ContractError::GatewayNotRegistered {})?;
        if info.is_frozen {
            return Err(ContractError::DomainFrozen {
                domain: source_domain,
            });
        }
        if info.incoming_gateway.is_frozen {
            return Err(ContractError::GatewayFrozen {});
        }

        let info = domains()
            .may_load(deps.storage, destination_domain.clone())?
            .ok_or(ContractError::DomainNotFound {})?;
        if info.is_frozen {
            return Err(ContractError::DomainFrozen {
                domain: destination_domain,
            });
        }
        let msg = Message {
            id,
            destination_address,
            destination_domain: destination_domain.clone(),
            source_domain,
            source_address,
            payload_hash,
        };

        if MESSAGES.may_load(deps.storage, msg.uuid())?.is_some() {
            return Err(ContractError::MessageAlreadyRouted { id: msg.uuid() });
        }
        MESSAGES.save(deps.storage, msg.uuid(), &())?;

        let qid = get_queue_id(&destination_domain);
        let q: VecDeque<Message> = VecDeque::new(&qid);
        q.push_back(deps.storage, &msg)?;

        Ok(Response::new().add_event(MessageRouted { msg }.into()))
    }

    pub fn consume_messages(
        deps: DepsMut,
        info: MessageInfo,
        count: Option<u32>,
    ) -> Result<Response, ContractError> {
        let domain = match find_domain_for_outgoing_gateway(&deps, &info.sender)? {
            None => return Err(ContractError::GatewayNotRegistered {}),
            Some((name, info)) => {
                if info.is_frozen {
                    return Err(ContractError::DomainFrozen { domain: name });
                } else if info.outgoing_gateway.is_frozen {
                    return Err(ContractError::GatewayFrozen {});
                } else {
                    name
                }
            }
        };
        let qid = get_queue_id(&domain);
        let q: VecDeque<Message> = VecDeque::new(&qid);
        let mut messages = vec![];

        let to_consume = if let Some(c) = count { c } else { u32::MAX };
        for _ in 0..to_consume {
            match q.pop_front(deps.storage)? {
                Some(m) => messages.push(m),
                None => break,
            }
        }
        Ok(Response::new()
            .add_events(Vec::<Event>::from(MessagesConsumed {
                domain,
                msgs: &messages,
            }))
            .set_data(to_binary(&messages)?))
    }

    pub fn require_admin(deps: &DepsMut, info: MessageInfo) -> Result<(), ContractError> {
        let config = CONFIG.load(deps.storage)?;
        if config.admin != info.sender {
            return Err(ContractError::Unauthorized {});
        }
        Ok(())
    }

    // queue id is just "[domain]-messages"
    pub fn get_queue_id(destination_domain: &DomainName) -> String {
        format!("{}-messages", destination_domain.to_string())
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, _msg: QueryMsg) -> StdResult<Binary> {
    todo!()
}

pub mod query {}
