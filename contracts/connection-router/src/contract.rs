#[cfg(not(feature = "library"))]
use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, Event, HexBinary, MessageInfo, Response,
    StdResult,
};
use cw_storage_plus::VecDeque;

use crate::error::ContractError;
use crate::events::{DomainRegistered, RouterInstantiated};
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{domains, Config, CONFIG, MESSAGES};

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
            destination_domain.parse()?,
            destination_address,
            source_address,
            payload_hash,
        ),
        ExecuteMsg::ConsumeMessages { count } => execute::consume_messages(deps, info, count),
    }
}

pub mod execute {

    use cosmwasm_std::Addr;

    use crate::{
        events::{
            DomainFrozen, DomainUnfrozen, GatewayFrozen, GatewayInfo, GatewayUnfrozen,
            GatewayUpgraded, MessageRouted, MessagesConsumed,
        },
        state::get_message_queue_id,
        types::{Domain, DomainName, Gateway, Message},
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
                    incoming: false,
                },
            }
            .into(),
        ))
    }

    pub fn freeze_domain(deps: DepsMut, domain: DomainName) -> Result<Response, ContractError> {
        domains().update(deps.storage, domain.clone(), |domain| match domain {
            None => Err(ContractError::DomainNotFound {}),
            Some(mut domain) => {
                domain.is_frozen = true;
                Ok(domain)
            }
        })?;
        Ok(Response::new().add_event(DomainFrozen { name: domain }.into()))
    }
    pub fn freeze_incoming_gateway(
        deps: DepsMut,
        domain_name: DomainName,
    ) -> Result<Response, ContractError> {
        let domain_info =
            domains().update(deps.storage, domain_name.clone(), |domain| match domain {
                None => Err(ContractError::DomainNotFound {}),
                Some(mut domain) => {
                    domain.incoming_gateway.is_frozen = true;
                    Ok(domain)
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
        let domain_info =
            domains().update(deps.storage, domain_name.clone(), |domain| match domain {
                None => Err(ContractError::DomainNotFound {}),
                Some(mut domain) => {
                    domain.outgoing_gateway.is_frozen = true;
                    Ok(domain)
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
        domains().update(deps.storage, domain_name.clone(), |domain| match domain {
            None => Err(ContractError::DomainNotFound {}),
            Some(mut domain) => {
                domain.is_frozen = false;
                Ok(domain)
            }
        })?;
        Ok(Response::new().add_event(DomainUnfrozen { name: domain_name }.into()))
    }
    pub fn unfreeze_incoming_gateway(
        deps: DepsMut,
        domain_name: DomainName,
    ) -> Result<Response, ContractError> {
        let domain_info =
            domains().update(deps.storage, domain_name.clone(), |domain| match domain {
                None => Err(ContractError::DomainNotFound {}),
                Some(mut domain) => {
                    domain.incoming_gateway.is_frozen = false;
                    Ok(domain)
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
        let domain_info =
            domains().update(deps.storage, domain_name.clone(), |domain| match domain {
                None => Err(ContractError::DomainNotFound {}),
                Some(mut domain) => {
                    domain.outgoing_gateway.is_frozen = false;
                    Ok(domain)
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

        let info = domains()
            .may_load(deps.storage, destination_domain.clone())?
            .ok_or(ContractError::DomainNotFound {})?;
        if info.is_frozen {
            return Err(ContractError::DomainFrozen {
                domain: destination_domain,
            });
        }
        let msg = Message::new(
            id.parse()?,
            destination_address,
            destination_domain.clone(),
            source_domain.name,
            source_address,
            payload_hash,
        );

        if MESSAGES.may_load(deps.storage, msg.id())?.is_some() {
            return Err(ContractError::MessageAlreadyRouted { id: msg.id() });
        }
        MESSAGES.save(deps.storage, msg.id(), &())?;

        let qid = get_message_queue_id(&destination_domain);
        let q: VecDeque<Message> = VecDeque::new(&qid);
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
        let q: VecDeque<Message> = VecDeque::new(&qid);
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
            .set_data(to_binary(&messages)?))
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
