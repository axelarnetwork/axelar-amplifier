#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Env, Event, MessageInfo, Response, StdResult,
};
use cw_storage_plus::Deque;

use crate::error::ContractError;
use crate::events::{DomainRegistered, RouterInstantiated};
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{domains, Config, Message, CONFIG, MESSAGES};

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
            execute::require_admin(&deps, info)?;
            let incoming_gateway_address = deps.api.addr_validate(&incoming_gateway_address)?;
            let outgoing_gateway_address = deps.api.addr_validate(&outgoing_gateway_address)?;
            execute::register_domain(
                deps,
                domain.parse()?,
                incoming_gateway_address,
                outgoing_gateway_address,
            )
        }
        ExecuteMsg::UpgradeIncomingGateway {
            domain,
            contract_address,
        } => {
            execute::require_admin(&deps, info)?;
            let contract_address = deps.api.addr_validate(&contract_address)?;
            execute::upgrade_incoming_gateway(deps, domain.parse()?, contract_address)
        }
        ExecuteMsg::UpgradeOutgoingGateway {
            domain,
            contract_address,
        } => {
            execute::require_admin(&deps, info)?;
            let contract_address = deps.api.addr_validate(&contract_address)?;
            execute::upgrade_outgoing_gateway(deps, domain.parse()?, contract_address)
        }
        ExecuteMsg::FreezeIncomingGateway { domain } => {
            execute::require_admin(&deps, info)?;
            execute::freeze_incoming_gateway(deps, domain.parse()?)
        }
        ExecuteMsg::FreezeOutgoingGateway { domain } => {
            execute::require_admin(&deps, info)?;
            execute::freeze_outgoing_gateway(deps, domain.parse()?)
        }
        ExecuteMsg::FreezeDomain { domain } => {
            execute::require_admin(&deps, info)?;
            execute::freeze_domain(deps, domain.parse()?)
        }
        ExecuteMsg::UnfreezeDomain { domain } => {
            execute::require_admin(&deps, info)?;
            execute::unfreeze_domain(deps, domain.parse()?)
        }
        ExecuteMsg::UnfreezeIncomingGateway { domain } => {
            execute::require_admin(&deps, info)?;
            execute::unfreeze_incoming_gateway(deps, domain.parse()?)
        }
        ExecuteMsg::UnfreezeOutgoingGateway { domain } => {
            execute::require_admin(&deps, info)?;
            execute::unfreeze_outgoing_gateway(deps, domain.parse()?)
        }
        ExecuteMsg::RouteMessage(msg) => {
            execute::route_message(deps, info, Message::try_from(msg)?)
        }
        ExecuteMsg::ConsumeMessages { count } => execute::consume_messages(deps, info, count),
    }
}

pub mod execute {

    use cosmwasm_std::Addr;

    use crate::{
        events::{
            DomainFrozen, DomainUnfrozen, GatewayDirection, GatewayFrozen, GatewayInfo,
            GatewayUnfrozen, GatewayUpgraded, MessageRouted, MessagesConsumed,
        },
        msg,
        state::{get_message_queue_id, Message},
        types::{Domain, DomainName, Gateway},
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
        domains().update(deps.storage, name.clone(), |domain| match domain {
            Some(_) => Err(ContractError::DomainAlreadyExists {}),
            None => Ok(Domain {
                name: name.clone(),
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
    ) -> StdResult<Option<Domain>> {
        domains()
            .idx
            .incoming_gateway
            .find_domain(deps, contract_address)
    }

    pub fn find_domain_for_outgoing_gateway(
        deps: &DepsMut,
        contract_address: &Addr,
    ) -> StdResult<Option<Domain>> {
        domains()
            .idx
            .outgoing_gateway
            .find_domain(deps, contract_address)
    }

    pub fn upgrade_incoming_gateway(
        deps: DepsMut,
        domain: DomainName,
        contract_address: Addr,
    ) -> Result<Response, ContractError> {
        if find_domain_for_incoming_gateway(&deps, &contract_address)?.is_some() {
            return Err(ContractError::GatewayAlreadyRegistered {});
        }
        domains().update(deps.storage, domain.clone(), |domain| match domain {
            None => Err(ContractError::DomainNotFound {}),
            Some(mut domain) => {
                domain.incoming_gateway.address = contract_address.clone();
                Ok(domain)
            }
        })?;
        Ok(Response::new().add_event(
            GatewayUpgraded {
                gateway: GatewayInfo {
                    domain,
                    gateway_address: contract_address,
                    direction: GatewayDirection::Incoming,
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
        domains().update(deps.storage, domain.clone(), |domain| match domain {
            None => Err(ContractError::DomainNotFound {}),
            Some(mut domain) => {
                domain.outgoing_gateway.address = contract_address.clone();
                Ok(domain)
            }
        })?;
        Ok(Response::new().add_event(
            GatewayUpgraded {
                gateway: GatewayInfo {
                    domain,
                    gateway_address: contract_address,
                    direction: GatewayDirection::Outgoing,
                },
            }
            .into(),
        ))
    }

    fn set_domain_frozen_status(
        deps: DepsMut,
        domain: &DomainName,
        is_frozen: bool,
    ) -> Result<Domain, ContractError> {
        domains().update(deps.storage, domain.clone(), |domain| match domain {
            None => Err(ContractError::DomainNotFound {}),
            Some(mut domain) => {
                domain.is_frozen = is_frozen;
                Ok(domain)
            }
        })
    }

    pub fn freeze_domain(deps: DepsMut, domain: DomainName) -> Result<Response, ContractError> {
        set_domain_frozen_status(deps, &domain, true)?;
        Ok(Response::new().add_event(DomainFrozen { name: domain }.into()))
    }

    pub fn unfreeze_domain(deps: DepsMut, domain: DomainName) -> Result<Response, ContractError> {
        set_domain_frozen_status(deps, &domain, false)?;
        Ok(Response::new().add_event(DomainUnfrozen { name: domain }.into()))
    }

    fn set_gateway_frozen_status(
        deps: DepsMut,
        domain_name: &DomainName,
        get_gateway: fn(&mut Domain) -> &mut Gateway,
        is_frozen: bool,
    ) -> Result<Domain, ContractError> {
        domains().update(deps.storage, domain_name.clone(), |domain| match domain {
            None => Err(ContractError::DomainNotFound {}),
            Some(mut domain) => {
                get_gateway(&mut domain).is_frozen = is_frozen;
                Ok(domain)
            }
        })
    }

    fn freeze_gateway(
        deps: DepsMut,
        domain_name: &DomainName,
        get_gateway: fn(&mut Domain) -> &mut Gateway,
    ) -> Result<Domain, ContractError> {
        set_gateway_frozen_status(deps, domain_name, get_gateway, true)
    }

    fn unfreeze_gateway(
        deps: DepsMut,
        domain_name: &DomainName,
        get_gateway: fn(&mut Domain) -> &mut Gateway,
    ) -> Result<Domain, ContractError> {
        set_gateway_frozen_status(deps, domain_name, get_gateway, false)
    }

    pub fn freeze_incoming_gateway(
        deps: DepsMut,
        domain_name: DomainName,
    ) -> Result<Response, ContractError> {
        let domain = freeze_gateway(deps, &domain_name, |domain: &mut Domain| {
            &mut domain.incoming_gateway
        })?;
        Ok(Response::new().add_event(
            GatewayFrozen {
                gateway: GatewayInfo {
                    domain: domain_name,
                    gateway_address: domain.incoming_gateway.address,
                    direction: GatewayDirection::Incoming,
                },
            }
            .into(),
        ))
    }

    pub fn freeze_outgoing_gateway(
        deps: DepsMut,
        domain_name: DomainName,
    ) -> Result<Response, ContractError> {
        let domain = freeze_gateway(deps, &domain_name, |domain: &mut Domain| {
            &mut domain.outgoing_gateway
        })?;
        Ok(Response::new().add_event(
            GatewayFrozen {
                gateway: GatewayInfo {
                    domain: domain_name,
                    gateway_address: domain.outgoing_gateway.address,
                    direction: GatewayDirection::Outgoing,
                },
            }
            .into(),
        ))
    }

    pub fn unfreeze_incoming_gateway(
        deps: DepsMut,
        domain_name: DomainName,
    ) -> Result<Response, ContractError> {
        let domain = unfreeze_gateway(deps, &domain_name, |domain: &mut Domain| {
            &mut domain.incoming_gateway
        })?;
        Ok(Response::new().add_event(
            GatewayUnfrozen {
                gateway: GatewayInfo {
                    domain: domain_name,
                    gateway_address: domain.incoming_gateway.address,
                    direction: GatewayDirection::Incoming,
                },
            }
            .into(),
        ))
    }

    pub fn unfreeze_outgoing_gateway(
        deps: DepsMut,
        domain_name: DomainName,
    ) -> Result<Response, ContractError> {
        let domain = unfreeze_gateway(deps, &domain_name, |domain: &mut Domain| {
            &mut domain.outgoing_gateway
        })?;
        Ok(Response::new().add_event(
            GatewayUnfrozen {
                gateway: GatewayInfo {
                    domain: domain_name,
                    gateway_address: domain.outgoing_gateway.address,
                    direction: GatewayDirection::Outgoing,
                },
            }
            .into(),
        ))
    }

    pub fn route_message(
        deps: DepsMut,
        info: MessageInfo,
        msg: Message,
    ) -> Result<Response, ContractError> {
        let source_domain = find_domain_for_incoming_gateway(&deps, &info.sender)?
            .ok_or(ContractError::GatewayNotRegistered {})?;
        if source_domain.is_frozen {
            return Err(ContractError::DomainFrozen {
                domain: source_domain.name,
            });
        }
        if source_domain.incoming_gateway.is_frozen {
            return Err(ContractError::GatewayFrozen {});
        }

        if source_domain.name != msg.source_domain {
            return Err(ContractError::WrongSourceDomain {});
        }

        let info = domains()
            .may_load(deps.storage, msg.destination_domain.clone())?
            .ok_or(ContractError::DomainNotFound {})?;
        if info.is_frozen {
            return Err(ContractError::DomainFrozen {
                domain: msg.destination_domain,
            });
        }

        if MESSAGES.may_load(deps.storage, msg.id())?.is_some() {
            return Err(ContractError::MessageAlreadyRouted { id: msg.id() });
        }
        MESSAGES.save(deps.storage, msg.id(), &())?;

        let qid = get_message_queue_id(&msg.destination_domain);
        let q: Deque<Message> = Deque::new(&qid);
        q.push_back(deps.storage, &msg)?;

        Ok(Response::new().add_event(MessageRouted { msg }.into()))
    }

    pub fn consume_messages(
        deps: DepsMut,
        info: MessageInfo,
        count: Option<u32>,
    ) -> Result<Response, ContractError> {
        let domain = find_domain_for_outgoing_gateway(&deps, &info.sender)?
            .ok_or(ContractError::GatewayNotRegistered {})?;
        if domain.is_frozen {
            return Err(ContractError::DomainFrozen {
                domain: domain.name,
            });
        }
        if domain.outgoing_gateway.is_frozen {
            return Err(ContractError::GatewayFrozen {});
        }

        let qid = get_message_queue_id(&domain.name);
        let q: Deque<Message> = Deque::new(&qid);
        let mut messages = vec![];

        let to_consume = count.unwrap_or(u32::MAX);
        for _ in 0..to_consume {
            match q.pop_front(deps.storage)? {
                Some(m) => messages.push(m),
                None => break,
            }
        }
        Ok(Response::new()
            .add_event(Event::from(MessagesConsumed {
                domain: domain.name,
                msgs: &messages,
            }))
            .set_data(to_binary(
                &messages
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<msg::Message>>(),
            )?))
    }

    pub fn require_admin(deps: &DepsMut, info: MessageInfo) -> Result<(), ContractError> {
        let config = CONFIG.load(deps.storage)?;
        if config.admin != info.sender {
            return Err(ContractError::Unauthorized {});
        }
        Ok(())
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, _msg: QueryMsg) -> StdResult<Binary> {
    todo!()
}

pub mod query {}
