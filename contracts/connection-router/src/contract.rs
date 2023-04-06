#[cfg(not(feature = "library"))]
use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Empty, Env, Event, HexBinary, MessageInfo,
    Order, Response, StdResult,
};
use cw2::{get_contract_version, set_contract_version};
use cw_storage_plus::VecDeque;
use semver::Version;
use sha256::digest;

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:connection-router";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{domains, Config, Domain, Message, CONFIG, MESSAGES};

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
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::new()
        .add_event(Event::new("router_instantiated").add_attribute("admin_address", admin)))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::RegisterDomain { domain } => {
            execute::is_admin(&deps, info)?;
            execute::register_domain(deps, domain)
        }
        ExecuteMsg::RegisterIncomingGateway {
            domain,
            contract_address,
        } => {
            execute::is_admin(&deps, info)?;
            execute::register_incoming_gateway(deps, domain, contract_address)
        }
        ExecuteMsg::RegisterOutgoingGateway {
            domain,
            contract_address,
        } => {
            execute::is_admin(&deps, info)?;
            execute::register_outgoing_gateway(deps, domain, contract_address)
        }
        ExecuteMsg::DeregisterDomain { domain } => {
            execute::is_admin(&deps, info)?;
            execute::deregister_domain(deps, domain)
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
            destination_domain,
            destination_address,
            source_address,
            payload_hash,
        ),
        ExecuteMsg::ConsumeMessages { count } => execute::consume_messages(deps, info, count),
        ExecuteMsg::RedeliverMessage { msg } => {
            execute::is_admin(&deps, info)?;
            execute::redeliver_message(deps, msg)
        }
    }
}

pub mod execute {

    use super::*;

    pub fn register_domain(deps: DepsMut, domain: String) -> Result<Response, ContractError> {
        domains().update(deps.storage, &domain, |e| match e {
            None => Ok(Domain {
                incoming_gateway: None,
                outgoing_gateway: None,
            }),
            Some(_) => Err(ContractError::DomainAlreadyExists {}),
        })?;
        Ok(Response::new()
            .add_event(Event::new("domain_registered").add_attribute("domain", domain)))
    }

    pub fn register_incoming_gateway(
        deps: DepsMut,
        domain: String,
        contract_address: String,
    ) -> Result<Response, ContractError> {
        let addr = deps.api.addr_validate(&contract_address)?;
        let matching_domains = &domains()
            .idx
            .incoming_gateway
            .prefix(contract_address.clone())
            .keys(deps.storage, None, None, Order::Ascending)
            .collect::<Result<Vec<String>, _>>()?;
        match &matching_domains[..] {
            [] => (),
            _ => return Err(ContractError::GatewayAlreadyRegistered {}),
        };
        domains().update(deps.storage, &domain, |e| match e {
            None => Err(ContractError::DomainNotFound {}),
            Some(mut d) => {
                d.incoming_gateway = Some(addr);
                Ok(d)
            }
        })?;
        Ok(Response::new().add_event(
            Event::new("incoming_gateway_registered")
                .add_attribute("domain", domain)
                .add_attribute("gateway_address", contract_address),
        ))
    }

    pub fn register_outgoing_gateway(
        deps: DepsMut,
        domain: String,
        contract_address: String,
    ) -> Result<Response, ContractError> {
        let addr = deps.api.addr_validate(&contract_address)?;
        let matching_domains = &domains()
            .idx
            .outgoing_gateway
            .prefix(contract_address.clone())
            .keys(deps.storage, None, None, Order::Ascending)
            .collect::<Result<Vec<String>, _>>()?;
        match &matching_domains[..] {
            [] => (),
            _ => return Err(ContractError::GatewayAlreadyRegistered {}),
        };
        domains().update(deps.storage, &domain, |e| match e {
            None => Err(ContractError::DomainNotFound {}),
            Some(mut d) => {
                d.outgoing_gateway = Some(addr);
                Ok(d)
            }
        })?;
        Ok(Response::new().add_event(
            Event::new("outgoing_gateway_registered")
                .add_attribute("domain", domain)
                .add_attribute("gateway_address", contract_address),
        ))
    }

    pub fn deregister_domain(deps: DepsMut, domain: String) -> Result<Response, ContractError> {
        domains().remove(deps.storage, &domain)?;
        Ok(Response::new()
            .add_event(Event::new("domain_deregistered").add_attribute("domain", domain)))
    }

    pub fn route_message(
        deps: DepsMut,
        info: MessageInfo,
        id: String,
        destination_domain: String,
        destination_address: String,
        source_address: String,
        payload_hash: HexBinary,
    ) -> Result<Response, ContractError> {
        let matching_domains = &domains()
            .idx
            .incoming_gateway
            .prefix(info.sender.into_string())
            .keys(deps.storage, None, None, Order::Ascending)
            .collect::<Result<Vec<String>, _>>()?;
        let source_domain = match &matching_domains[..] {
            [d] => d,
            _ => return Err(ContractError::GatewayNotRegistered {}),
        };
        match domains().may_load(deps.storage, &destination_domain)? {
            Some(_) => (),
            None => return Err(ContractError::DomainNotFound {}),
        }
        let msg = Message {
            id,
            destination_address,
            destination_domain: destination_domain.clone(),
            source_domain: source_domain.clone(),
            source_address,
            payload_hash,
            redelivered: false,
        };
        if let Ok(Some(_)) = MESSAGES.may_load(deps.storage, msg.uuid()) {
            return Err(ContractError::MessageAlreadyRouted { id: msg.uuid() });
        }

        let h = digest((to_binary(&msg)?).to_string());
        MESSAGES.save(deps.storage, msg.uuid(), &h)?;
        let qid = get_queue_id(&destination_domain);
        let q: VecDeque<Message> = VecDeque::new(&qid);
        q.push_back(deps.storage, &msg)?;
        Ok(Response::new().add_event(create_message_event("message_routed", &msg)))
    }

    pub fn consume_messages(
        deps: DepsMut,
        info: MessageInfo,
        count: u32,
    ) -> Result<Response, ContractError> {
        let matching_domains = &domains()
            .idx
            .outgoing_gateway
            .prefix(info.sender.into_string())
            .range(deps.storage, None, None, Order::Ascending)
            .collect::<Result<Vec<(String, Domain)>, _>>()?;
        let domain = match &matching_domains[..] {
            [(name, _)] => name,
            _ => return Err(ContractError::GatewayNotRegistered {}),
        };
        let qid = get_queue_id(domain);
        let q: VecDeque<Message> = VecDeque::new(&qid);
        let mut messages = vec![];

        let mut res = Response::new();
        for _ in 0..count {
            let elt = q.pop_front(deps.storage)?;
            match elt {
                Some(m) => {
                    // need the events to have different names, so we append message id
                    let mut event_name = String::from("message_consumed_");
                    event_name.push_str(&m.id.clone());
                    res = res.add_event(create_message_event(&event_name, &m));
                    messages.push(m)
                }
                None => break,
            }
        }
        Ok(res
            .add_event(
                Event::new("messages_consumed")
                    .add_attribute("domain", domain)
                    .add_attribute("count", messages.len().to_string()),
            )
            .set_data(to_binary(&messages)?))
    }

    pub fn redeliver_message(deps: DepsMut, mut msg: Message) -> Result<Response, ContractError> {
        let expected_hash = match MESSAGES.may_load(deps.storage, msg.uuid())? {
            Some(hash) => hash,
            None => return Err(ContractError::MessageNotFound {}),
        };

        let h = digest((to_binary(&msg)?).to_string());
        if expected_hash != h {
            return Err(ContractError::MessageHashMismatch {});
        }

        let qid = get_queue_id(&msg.destination_domain);
        let q: VecDeque<Message> = VecDeque::new(&qid);
        msg.redelivered = true;
        q.push_back(deps.storage, &msg)?;
        Ok(Response::new().add_event(create_message_event("message_redelivered", &msg)))
    }

    pub fn is_admin(deps: &DepsMut, info: MessageInfo) -> Result<Response, ContractError> {
        let config = CONFIG.load(deps.storage)?;
        if config.admin != info.sender {
            return Err(ContractError::Unauthorized {});
        }
        Ok(Response::new())
    }

    // queue id is just "[domain]-messages"
    pub fn get_queue_id(destination_domain: &str) -> String {
        let mut qid = destination_domain.to_owned();
        qid.push_str("-messages");
        qid
    }

    fn create_message_event(event_name: &str, msg: &Message) -> Event {
        let event = Event::new(event_name);
        event
            .add_attribute("id", msg.id.clone())
            .add_attribute("source_domain", msg.source_domain.clone())
            .add_attribute("source_addressess", msg.source_address.clone())
            .add_attribute("destination_domain", msg.destination_domain.clone())
            .add_attribute("destination_addressess", msg.destination_address.clone())
            .add_attribute("payload_hash", msg.payload_hash.to_string())
            .add_attribute("redelivered", msg.redelivered.to_string())
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetDomains {} => to_binary(&query::get_domains(deps)?),
        QueryMsg::GetPendingMessages { domain } => {
            to_binary(&query::get_pending_messages(deps, domain)?)
        }
    }
}

pub mod query {
    use super::*;

    pub fn get_domains(deps: Deps) -> StdResult<Vec<(String, Domain)>> {
        let domains: StdResult<Vec<(String, Domain)>> = domains()
            .range(deps.storage, None, None, Order::Ascending)
            .collect();
        domains
    }

    pub fn get_pending_messages(deps: Deps, domain: String) -> StdResult<Vec<Message>> {
        let qid = execute::get_queue_id(&domain);
        let queue: VecDeque<Message> = VecDeque::new(&qid);
        let mut messages = vec![];

        for x in 0..256 {
            let elt = queue.get(deps.storage, x)?;
            match elt {
                Some(m) => messages.push(m),
                None => break,
            }
        }
        Ok(messages)
    }
}

#[entry_point]
pub fn migrate(deps: DepsMut, _env: Env, _msg: Empty) -> Result<Response, ContractError> {
    let version: Version = CONTRACT_VERSION.parse()?;
    let storage_version: Version = get_contract_version(deps.storage)?.version.parse()?;

    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::new().add_event(
        Event::new("contract_migrated")
            .add_attribute("new_version", version.to_string())
            .add_attribute("old_version", storage_version.to_string()),
    ))
}
