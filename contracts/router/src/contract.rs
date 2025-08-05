use axelar_wasm_std::{address, killswitch, permission_control, FnExt};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, Storage,
};
use error_stack::ResultExt;
use msgs_derive::ensure_permissions;
use router_api::error::Error;

use crate::msg::{ExecuteMsg, ExecuteMsgFromProxy, InstantiateMsg, QueryMsg};
use crate::state::{load_chain_by_gateway, load_config, Config};
use crate::{state, Event};

mod execute;
mod migrations;
mod query;

pub use migrations::{migrate, MigrateMsg};

pub const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
pub const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let admin = address::validate_cosmwasm_address(deps.api, &msg.admin_address)?;
    let governance = address::validate_cosmwasm_address(deps.api, &msg.governance_address)?;
    let axelarnet_gateway = address::validate_cosmwasm_address(deps.api, &msg.axelarnet_gateway)?;
    let coordinator = address::validate_cosmwasm_address(deps.api, &msg.coordinator_address)?;

    permission_control::set_admin(deps.storage, &admin)?;
    permission_control::set_governance(deps.storage, &governance)?;

    let config = Config {
        axelarnet_gateway: axelarnet_gateway.clone(),
        coordinator: coordinator.clone(),
    };

    state::save_config(deps.storage, &config)?;
    killswitch::init(deps.storage, killswitch::State::Disengaged)?;

    Ok(Response::new().add_event(Event::RouterInstantiated {
        admin_address: admin,
        governance_address: governance,
    }))
}

#[ensure_permissions(proxy(coordinator = find_coordinator_address), direct(gateway = find_gateway_address(&info.sender)))]
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    match msg {
        ExecuteMsg::RegisterChain {
            chain,
            gateway_address,
            msg_id_format,
        } => {
            let gateway_address = address::validate_cosmwasm_address(deps.api, &gateway_address)?;
            Ok(execute::register_chain(
                deps.storage,
                deps.querier,
                chain,
                gateway_address,
                msg_id_format,
            )?)
        }
        ExecuteMsg::UpgradeGateway {
            chain,
            contract_address,
        } => {
            let contract_address = address::validate_cosmwasm_address(deps.api, &contract_address)?;
            execute::upgrade_gateway(deps.storage, chain, contract_address)
        }
        ExecuteMsg::FreezeChains { chains } => execute::freeze_chains(deps.storage, chains),
        ExecuteMsg::UnfreezeChains { chains } => execute::unfreeze_chains(deps.storage, chains),
        ExecuteMsg::RouteMessages(msgs) => Ok(execute::route_messages(
            deps.storage,
            deps.querier,
            info.sender,
            msgs,
        )?),
        ExecuteMsg::DisableRouting => execute::disable_routing(deps.storage),
        ExecuteMsg::EnableRouting => execute::enable_routing(deps.storage),
    }?
    .then(Ok)
}

fn find_gateway_address(
    sender: &Addr,
) -> impl FnOnce(&dyn Storage, &ExecuteMsg) -> error_stack::Result<Addr, Error> + '_ {
    move |storage, _| {
        let axelarnet_gateway = load_config(storage)?.axelarnet_gateway;
        if axelarnet_gateway == sender {
            Ok(axelarnet_gateway)
        } else {
            load_chain_by_gateway(storage, sender)?
                .gateway
                .address
                .then(Ok)
        }
    }
}

fn find_coordinator_address(storage: &dyn Storage) -> error_stack::Result<Addr, Error> {
    Ok(load_config(storage)
        .change_context(Error::CoordinatorNotFound)?
        .coordinator)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps,
    _env: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::error::ContractError> {
    match msg {
        QueryMsg::ChainInfo(chain) => to_json_binary(&query::chain_info(deps.storage, chain)?),
        QueryMsg::Chains { start_after, limit } => {
            to_json_binary(&query::chains(deps.storage, start_after, limit)?)
        }
        QueryMsg::IsEnabled => to_json_binary(&killswitch::is_contract_active(deps.storage)),
    }
    .map_err(axelar_wasm_std::error::ContractError::from)
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::str::FromStr;

    use axelar_core_std::nexus::test_utils::reply_with_is_chain_registered;
    use axelar_wasm_std::err_contains;
    use axelar_wasm_std::error::ContractError;
    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use cosmwasm_std::testing::{
        message_info, mock_dependencies, mock_env, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{from_json, Addr, CosmosMsg, Empty, OwnedDeps, WasmMsg};
    use permission_control::Permission;
    use router_api::error::Error;
    use router_api::{
        ChainEndpoint, ChainName, CrossChainId, GatewayDirection, Message, FIELD_DELIMITER,
    };

    use super::*;
    use crate::Event;

    const ADMIN_ADDRESS: &str = "admin";
    const GOVERNANCE_ADDRESS: &str = "governance";
    const AXELARNET_GATEWAY_ADDRESS: &str = "axelarnet_gateway";
    const COORDINATOR_ADDRESS: &str = "coordinator";
    const UNAUTHORIZED_ADDRESS: &str = "unauthorized";

    fn setup() -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = mock_dependencies();
        let api = deps.api;
        deps.querier = deps
            .querier
            .with_custom_handler(reply_with_is_chain_registered(false));

        instantiate(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            InstantiateMsg {
                admin_address: api.addr_make(ADMIN_ADDRESS).to_string(),
                governance_address: api.addr_make(GOVERNANCE_ADDRESS).to_string(),
                axelarnet_gateway: api.addr_make(AXELARNET_GATEWAY_ADDRESS).to_string(),
                coordinator_address: api.addr_make(COORDINATOR_ADDRESS).to_string(),
            },
        )
        .unwrap();

        deps
    }

    struct Chain {
        chain_name: ChainName,
        gateway: Addr,
    }

    fn make_chain(name: &str) -> Chain {
        Chain {
            chain_name: name.parse().unwrap(),
            gateway: MockApi::default().addr_make(name),
        }
    }

    fn register_chain(deps: DepsMut, chain: &Chain) {
        execute(
            deps,
            mock_env(),
            message_info(&MockApi::default().addr_make(GOVERNANCE_ADDRESS), &[]),
            ExecuteMsg::RegisterChain {
                chain: chain.chain_name.clone(),
                gateway_address: chain.gateway.to_string().try_into().unwrap(),
                msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
            }
            .into(),
        )
        .unwrap();
    }

    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
    fn generate_messages(
        src_chain: &Chain,
        dest_chain: &Chain,
        nonce: &mut usize,
        count: usize,
    ) -> Vec<Message> {
        let mut msgs = vec![];
        for x in 0..count {
            *nonce += 1;
            let id = HexTxHashAndEventIndex {
                tx_hash: [*nonce as u8; 32],
                event_index: 0,
            }
            .to_string();
            msgs.push(Message {
                cc_id: CrossChainId::new(src_chain.chain_name.clone(), id).unwrap(),
                destination_address: "idc".parse().unwrap(),
                destination_chain: dest_chain.chain_name.clone(),
                source_address: "idc".parse().unwrap(),
                payload_hash: [x as u8; 32],
            })
        }
        msgs
    }

    pub fn assert_contract_err_string_contains(
        actual: impl Into<ContractError>,
        expected: impl Into<ContractError>,
    ) {
        assert!(actual
            .into()
            .to_string()
            .contains(&expected.into().to_string()));
    }

    pub fn assert_messages_in_cosmos_msg(
        contract_addr: Addr,
        messages: Vec<Message>,
        cosmos_msg: &CosmosMsg,
    ) {
        assert_eq!(
            &CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: contract_addr.to_string(),
                msg: to_json_binary(&gateway_api::msg::ExecuteMsg::RouteMessages(messages,))
                    .unwrap(),
                funds: vec![],
            }),
            cosmos_msg
        );
    }

    #[test]
    fn successful_routing() {
        let mut deps = setup();
        let eth = make_chain("ethereum");
        let polygon = make_chain("polygon");

        register_chain(deps.as_mut(), &eth);
        register_chain(deps.as_mut(), &polygon);

        let nonce: &mut usize = &mut 0;
        let messages = generate_messages(&eth, &polygon, nonce, 255);

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&eth.gateway, &[]),
            ExecuteMsg::RouteMessages(messages.clone()).into(),
        )
        .unwrap();

        assert_eq!(res.messages.len(), 1);
        assert_messages_in_cosmos_msg(polygon.gateway, messages.clone(), &res.messages[0].msg);

        // try to route twice
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&eth.gateway, &[]),
            ExecuteMsg::RouteMessages(messages.clone()).into(),
        );

        assert!(res.is_ok(), "{:?}", res);
    }

    #[test]
    fn wrong_source_chain() {
        let mut deps = setup();
        let eth = make_chain("ethereum");
        let polygon = make_chain("polygon");

        register_chain(deps.as_mut(), &eth);
        register_chain(deps.as_mut(), &polygon);

        let messages = generate_messages(&eth, &polygon, &mut 0, 1);

        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&polygon.gateway, &[]),
            ExecuteMsg::RouteMessages(messages).into(),
        )
        .unwrap_err();

        assert_contract_err_string_contains(err, Error::WrongSourceChain);
    }

    #[test]
    fn amplifier_messages_must_have_lower_case() {
        let mut deps = setup();
        let eth = make_chain("ethereum");
        let polygon = make_chain("polygon");

        register_chain(deps.as_mut(), &eth);
        register_chain(deps.as_mut(), &polygon);

        let mut messages = generate_messages(&eth, &polygon, &mut 0, 1);
        messages
            .iter_mut()
            .for_each(|msg| msg.cc_id.source_chain = "Ethereum".parse().unwrap());

        let result = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&eth.gateway, &[]),
            ExecuteMsg::RouteMessages(messages).into(),
        )
        .unwrap_err();
        assert!(err_contains!(result.report, Error, Error::WrongSourceChain));
    }

    #[test]
    fn nexus_messages_can_have_upper_case() {
        let mut deps = setup();
        let api = deps.api;
        let eth = make_chain("ethereum");
        let polygon = make_chain("polygon");

        register_chain(deps.as_mut(), &polygon);

        let mut messages = generate_messages(&eth, &polygon, &mut 0, 1);
        messages
            .iter_mut()
            .for_each(|msg| msg.cc_id.source_chain = "Ethereum".parse().unwrap());

        let result = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(AXELARNET_GATEWAY_ADDRESS), &[]),
            ExecuteMsg::RouteMessages(messages.clone()).into(),
        );
        assert!(result.is_ok());
        assert_messages_in_cosmos_msg(polygon.gateway, messages, &result.unwrap().messages[0].msg);
    }

    #[test]
    fn multi_chain_route() {
        let mut deps = setup();
        let chains = vec![
            make_chain("ethereum"),
            make_chain("polygon"),
            make_chain("osmosis"),
            make_chain("avalanche"),
            make_chain("moonbeam"),
        ];
        for c in &chains {
            register_chain(deps.as_mut(), c);
        }

        let nonce = &mut 0;
        let mut all_msgs_by_dest = HashMap::new();
        let mut all_msgs_by_src = HashMap::new();
        for d in &chains {
            let mut msgs = vec![];
            for s in &chains {
                let sending = generate_messages(s, d, nonce, 50);

                all_msgs_by_src
                    .entry(s.chain_name.to_string())
                    .or_insert(vec![])
                    .append(&mut sending.clone());

                msgs.append(&mut sending.clone());
            }
            all_msgs_by_dest.insert(d.chain_name.to_string(), msgs);
        }

        for s in &chains {
            let res = execute(
                deps.as_mut(),
                mock_env(),
                message_info(&s.gateway, &[]),
                ExecuteMsg::RouteMessages(
                    all_msgs_by_src
                        .get(&s.chain_name.to_string())
                        .unwrap()
                        .clone(),
                )
                .into(),
            )
            .unwrap();

            assert_eq!(res.messages.len(), chains.len());

            for (i, d) in chains.iter().enumerate() {
                assert_messages_in_cosmos_msg(
                    d.gateway.clone(),
                    all_msgs_by_dest
                        .get(&d.chain_name.to_string())
                        .unwrap()
                        .clone()
                        .into_iter()
                        .filter(|m| m.cc_id.source_chain == s.chain_name)
                        .collect::<Vec<_>>(),
                    &res.messages[i].msg,
                );
            }
        }
    }

    #[test]
    fn authorization() {
        let mut deps = setup();
        let api = deps.api;
        let chain = make_chain("ethereum");

        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(UNAUTHORIZED_ADDRESS), &[]),
            ExecuteMsg::RegisterChain {
                chain: chain.chain_name.clone(),
                gateway_address: chain.gateway.to_string().try_into().unwrap(),
                msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
            }
            .into(),
        )
        .unwrap_err();
        assert_contract_err_string_contains(
            err,
            permission_control::Error::PermissionDenied {
                expected: Permission::Governance.into(),
                actual: Permission::NoPrivilege.into(),
            },
        );

        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::RegisterChain {
                chain: chain.chain_name.clone(),
                gateway_address: chain.gateway.to_string().try_into().unwrap(),
                msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
            }
            .into(),
        )
        .unwrap_err();
        assert_contract_err_string_contains(
            err,
            permission_control::Error::PermissionDenied {
                expected: Permission::Governance.into(),
                actual: Permission::Admin.into(),
            },
        );

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(GOVERNANCE_ADDRESS), &[]),
            ExecuteMsg::RegisterChain {
                chain: chain.chain_name.clone(),
                gateway_address: chain.gateway.to_string().try_into().unwrap(),
                msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
            }
            .into(),
        );
        assert!(res.is_ok());

        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(UNAUTHORIZED_ADDRESS), &[]),
            ExecuteMsg::FreezeChains {
                chains: HashMap::from([(
                    chain.chain_name.clone(),
                    GatewayDirection::Bidirectional,
                )]),
            }
            .into(),
        )
        .unwrap_err();

        assert_contract_err_string_contains(
            err,
            permission_control::Error::PermissionDenied {
                expected: Permission::Elevated.into(),
                actual: Permission::NoPrivilege.into(),
            },
        );

        assert!(execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(GOVERNANCE_ADDRESS), &[]),
            ExecuteMsg::FreezeChains {
                chains: HashMap::from([(
                    chain.chain_name.clone(),
                    GatewayDirection::Bidirectional,
                )]),
            }
            .into(),
        )
        .is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::FreezeChains {
                chains: HashMap::from([(
                    chain.chain_name.clone(),
                    GatewayDirection::Bidirectional,
                )]),
            }
            .into(),
        );
        assert!(res.is_ok());

        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(UNAUTHORIZED_ADDRESS), &[]),
            ExecuteMsg::FreezeChains {
                chains: HashMap::from([(chain.chain_name.clone(), GatewayDirection::None)]),
            }
            .into(),
        )
        .unwrap_err();
        assert_contract_err_string_contains(
            err,
            permission_control::Error::PermissionDenied {
                expected: Permission::Elevated.into(),
                actual: Permission::NoPrivilege.into(),
            },
        );

        assert!(execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(GOVERNANCE_ADDRESS), &[]),
            ExecuteMsg::FreezeChains {
                chains: HashMap::from([(chain.chain_name.clone(), GatewayDirection::None)]),
            }
            .into(),
        )
        .is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::FreezeChains {
                chains: HashMap::from([(chain.chain_name.clone(), GatewayDirection::None)]),
            }
            .into(),
        );
        assert!(res.is_ok());

        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(UNAUTHORIZED_ADDRESS), &[]),
            ExecuteMsg::UpgradeGateway {
                chain: chain.chain_name.clone(),
                contract_address: MockApi::default()
                    .addr_make("new gateway")
                    .to_string()
                    .try_into()
                    .unwrap(),
            }
            .into(),
        )
        .unwrap_err();
        assert_contract_err_string_contains(
            err,
            permission_control::Error::PermissionDenied {
                expected: Permission::Governance.into(),
                actual: Permission::NoPrivilege.into(),
            },
        );

        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::UpgradeGateway {
                chain: chain.chain_name.clone(),
                contract_address: MockApi::default()
                    .addr_make("new gateway")
                    .to_string()
                    .try_into()
                    .unwrap(),
            }
            .into(),
        )
        .unwrap_err();
        assert_contract_err_string_contains(
            err,
            permission_control::Error::PermissionDenied {
                expected: Permission::Governance.into(),
                actual: Permission::Admin.into(),
            },
        );

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(GOVERNANCE_ADDRESS), &[]),
            ExecuteMsg::UpgradeGateway {
                chain: chain.chain_name.clone(),
                contract_address: MockApi::default()
                    .addr_make("new gateway")
                    .to_string()
                    .try_into()
                    .unwrap(),
            }
            .into(),
        );
        assert!(res.is_ok());
    }

    #[test]
    fn upgrade_gateway_outgoing() {
        let mut deps = setup();
        let api = deps.api;
        let eth = make_chain("ethereum");
        let polygon = make_chain("polygon");

        register_chain(deps.as_mut(), &eth);
        register_chain(deps.as_mut(), &polygon);
        let new_gateway = MockApi::default().addr_make("new-gateway");

        let _ = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(GOVERNANCE_ADDRESS), &[]),
            ExecuteMsg::UpgradeGateway {
                chain: polygon.chain_name.clone(),
                contract_address: new_gateway.to_string().try_into().unwrap(),
            }
            .into(),
        )
        .unwrap();

        let messages = &generate_messages(&eth, &polygon, &mut 0, 1);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&eth.gateway, &[]),
            ExecuteMsg::RouteMessages(messages.clone()).into(),
        )
        .unwrap();

        assert_eq!(res.messages.len(), 1);
        assert_messages_in_cosmos_msg(new_gateway, messages.clone(), &res.messages[0].msg);
    }

    #[test]
    fn upgrade_gateway_incoming() {
        let mut deps = setup();
        let api = deps.api;
        let eth = make_chain("ethereum");
        let polygon = make_chain("polygon");

        register_chain(deps.as_mut(), &eth);
        register_chain(deps.as_mut(), &polygon);
        let new_gateway = MockApi::default().addr_make("new-gateway");

        let _ = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(GOVERNANCE_ADDRESS), &[]),
            ExecuteMsg::UpgradeGateway {
                chain: polygon.chain_name.clone(),
                contract_address: new_gateway.to_string().try_into().unwrap(),
            }
            .into(),
        )
        .unwrap();

        let messages = &generate_messages(&polygon, &eth, &mut 0, 1);
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&polygon.gateway, &[]),
            ExecuteMsg::RouteMessages(messages.clone()).into(),
        )
        .unwrap_err();
        assert_contract_err_string_contains(err, Error::GatewayNotRegistered);

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&new_gateway, &[]),
            ExecuteMsg::RouteMessages(messages.clone()).into(),
        )
        .unwrap();

        assert_eq!(res.messages.len(), 1);
        assert_messages_in_cosmos_msg(eth.gateway, messages.clone(), &res.messages[0].msg);
    }

    #[test]
    fn register_chain_test() {
        let mut deps = setup();
        let eth = make_chain("ethereum");
        let polygon = make_chain("polygon");

        let message = &generate_messages(&eth, &polygon, &mut 0, 1)[0];
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&eth.gateway, &[]),
            ExecuteMsg::RouteMessages(vec![message.clone()]).into(),
        )
        .unwrap_err();
        assert_contract_err_string_contains(
            err,
            permission_control::Error::WhitelistNotFound {
                sender: eth.gateway.clone(),
            },
        );

        register_chain(deps.as_mut(), &eth);
        register_chain(deps.as_mut(), &polygon);

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&eth.gateway, &[]),
            ExecuteMsg::RouteMessages(vec![message.clone()]).into(),
        );
        assert!(res.is_ok());
    }

    #[test]
    fn chain_already_registered() {
        let mut deps = setup();
        let api = deps.api;
        let eth = make_chain("ethereum");
        register_chain(deps.as_mut(), &eth);

        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(GOVERNANCE_ADDRESS), &[]),
            ExecuteMsg::RegisterChain {
                chain: eth.chain_name,
                gateway_address: MockApi::default()
                    .addr_make("new gateway")
                    .to_string()
                    .try_into()
                    .unwrap(),
                msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
            }
            .into(),
        )
        .unwrap_err();
        assert_contract_err_string_contains(err, Error::ChainAlreadyExists);

        // case insensitive
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(GOVERNANCE_ADDRESS), &[]),
            ExecuteMsg::RegisterChain {
                chain: ChainName::from_str("ETHEREUM").unwrap(),
                gateway_address: MockApi::default()
                    .addr_make("new gateway")
                    .to_string()
                    .try_into()
                    .unwrap(),
                msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
            }
            .into(),
        )
        .unwrap_err();
        assert_contract_err_string_contains(err, Error::ChainAlreadyExists);
    }

    #[test]
    fn invalid_chain_name() {
        assert_contract_err_string_contains(
            ChainName::from_str(format!("bad{}", FIELD_DELIMITER).as_str()).unwrap_err(),
            Error::InvalidChainName,
        );

        assert_contract_err_string_contains(
            ChainName::from_str("").unwrap_err(),
            Error::InvalidChainName,
        );
    }

    #[test]
    fn gateway_already_registered() {
        let mut deps = setup();
        let api = deps.api;
        let eth = make_chain("ethereum");
        let polygon = make_chain("polygon");
        register_chain(deps.as_mut(), &eth);

        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(GOVERNANCE_ADDRESS), &[]),
            ExecuteMsg::RegisterChain {
                chain: polygon.chain_name.clone(),
                gateway_address: eth.gateway.to_string().try_into().unwrap(),
                msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
            }
            .into(),
        )
        .unwrap_err();
        assert_contract_err_string_contains(err, Error::GatewayAlreadyRegistered);

        register_chain(deps.as_mut(), &polygon);
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(GOVERNANCE_ADDRESS), &[]),
            ExecuteMsg::UpgradeGateway {
                chain: eth.chain_name,
                contract_address: polygon.gateway.to_string().try_into().unwrap(),
            }
            .into(),
        )
        .unwrap_err();

        assert_contract_err_string_contains(err, Error::GatewayAlreadyRegistered);
    }

    #[test]
    fn freeze_incoming() {
        let mut deps = setup();
        let api = deps.api;
        let eth = make_chain("ethereum");
        let polygon = make_chain("polygon");
        register_chain(deps.as_mut(), &eth);
        register_chain(deps.as_mut(), &polygon);

        let _ = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::FreezeChains {
                chains: HashMap::from([(polygon.chain_name.clone(), GatewayDirection::Incoming)]),
            }
            .into(),
        )
        .unwrap();

        // can't route from frozen incoming gateway
        let message = &generate_messages(&polygon, &eth, &mut 0, 1)[0];
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&polygon.gateway, &[]),
            ExecuteMsg::RouteMessages(vec![message.clone()]).into(),
        )
        .unwrap_err();
        assert_contract_err_string_contains(
            err,
            Error::ChainFrozen {
                chain: polygon.chain_name.clone(),
            },
        );

        let messages = &generate_messages(&eth, &polygon, &mut 0, 1);
        // can still route to chain
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&eth.gateway, &[]),
            ExecuteMsg::RouteMessages(messages.clone()).into(),
        )
        .unwrap();

        assert_eq!(res.messages.len(), 1);
        assert_messages_in_cosmos_msg(
            polygon.gateway.clone(),
            messages.clone(),
            &res.messages[0].msg,
        );

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::UnfreezeChains {
                chains: HashMap::from([(polygon.chain_name.clone(), GatewayDirection::Incoming)]),
            }
            .into(),
        );
        assert!(res.is_ok());

        let message = &generate_messages(&polygon, &eth, &mut 0, 1)[0];
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&polygon.gateway, &[]),
            ExecuteMsg::RouteMessages(vec![message.clone()]).into(),
        );
        assert!(res.is_ok());
    }

    #[test]
    fn freeze_outgoing() {
        let mut deps = setup();
        let api = deps.api;
        let eth = make_chain("ethereum");
        let polygon = make_chain("polygon");
        register_chain(deps.as_mut(), &eth);
        register_chain(deps.as_mut(), &polygon);

        // freeze outgoing
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::FreezeChains {
                chains: HashMap::from([(polygon.chain_name.clone(), GatewayDirection::Outgoing)]),
            }
            .into(),
        );
        assert!(res.is_ok());

        // can still send to the chain, messages will queue up
        let messages = &generate_messages(&eth, &polygon, &mut 0, 1);
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&eth.gateway, &[]),
            ExecuteMsg::RouteMessages(messages.clone()).into(),
        )
        .unwrap_err();
        assert_contract_err_string_contains(
            err,
            Error::ChainFrozen {
                chain: polygon.chain_name.clone(),
            },
        );

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::UnfreezeChains {
                chains: HashMap::from([(polygon.chain_name.clone(), GatewayDirection::Outgoing)]),
            }
            .into(),
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&eth.gateway, &[]),
            ExecuteMsg::RouteMessages(messages.clone()).into(),
        )
        .unwrap();

        assert_eq!(res.messages.len(), 1);
        assert_messages_in_cosmos_msg(polygon.gateway, messages.clone(), &res.messages[0].msg);
    }

    #[test]
    fn freeze_chain() {
        let mut deps = setup();
        let api = deps.api;
        let eth = make_chain("ethereum");
        let polygon = make_chain("polygon");
        register_chain(deps.as_mut(), &eth);
        register_chain(deps.as_mut(), &polygon);

        let nonce = &mut 0;

        // route a message first
        let routed_msg = &generate_messages(&eth, &polygon, nonce, 1)[0];
        let _ = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&eth.gateway, &[]),
            ExecuteMsg::RouteMessages(vec![routed_msg.clone()]).into(),
        )
        .unwrap();

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::FreezeChains {
                chains: HashMap::from([(
                    polygon.chain_name.clone(),
                    GatewayDirection::Bidirectional,
                )]),
            }
            .into(),
        );
        assert!(res.is_ok());

        let msg = &generate_messages(&eth, &polygon, nonce, 1)[0];
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&eth.gateway, &[]),
            ExecuteMsg::RouteMessages(vec![msg.clone()]).into(),
        )
        .unwrap_err();
        // can't route to frozen chain
        assert_contract_err_string_contains(
            err,
            Error::ChainFrozen {
                chain: polygon.chain_name.clone(),
            },
        );

        // can't route from frozen chain
        let message = &generate_messages(&polygon, &eth, nonce, 1)[0];
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&polygon.gateway, &[]),
            ExecuteMsg::RouteMessages(vec![message.clone()]).into(),
        )
        .unwrap_err();
        assert_contract_err_string_contains(
            err,
            Error::ChainFrozen {
                chain: polygon.chain_name.clone(),
            },
        );

        // unfreeze and test that everything works correctly
        let _ = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::UnfreezeChains {
                chains: HashMap::from([(
                    polygon.chain_name.clone(),
                    GatewayDirection::Bidirectional,
                )]),
            }
            .into(),
        )
        .unwrap();

        // can route to the chain now
        let message = &generate_messages(&eth, &polygon, nonce, 1)[0];
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&eth.gateway, &[]),
            ExecuteMsg::RouteMessages(vec![message.clone()]).into(),
        );
        assert!(res.is_ok());

        // can route from the chain
        let message = &generate_messages(&polygon, &eth, nonce, 1)[0];
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&polygon.gateway, &[]),
            ExecuteMsg::RouteMessages(vec![message.clone()]).into(),
        );
        assert!(res.is_ok());
    }

    #[test]
    fn freeze_and_unfreeze_all_chains() {
        let eth = make_chain("ethereum");
        let polygon = make_chain("polygon");
        let test_case = HashMap::from([
            (eth.chain_name.clone(), GatewayDirection::Bidirectional),
            (polygon.chain_name.clone(), GatewayDirection::Bidirectional),
        ]);

        let mut deps = setup();
        let api = deps.api;

        register_chain(deps.as_mut(), &eth);
        register_chain(deps.as_mut(), &polygon);

        let chains = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::Chains {
                start_after: None,
                limit: None,
            },
        )
        .unwrap()
        .then(|chains| from_json::<Vec<ChainEndpoint>>(&chains))
        .unwrap();

        for chain in chains.iter() {
            assert!(!chain.incoming_frozen() && !chain.outgoing_frozen())
        }

        type Check = fn(&Result<Response, ContractError>) -> bool; // clippy complains without the alias about complex types

        // try sender without permission
        let permission_control: Vec<(Addr, Check)> = vec![
            (api.addr_make(UNAUTHORIZED_ADDRESS), Result::is_err),
            (api.addr_make(GOVERNANCE_ADDRESS), Result::is_ok),
            (api.addr_make(ADMIN_ADDRESS), Result::is_ok),
        ];

        for permission_case in permission_control.iter() {
            let (sender, result_check) = permission_case;
            let res = execute(
                deps.as_mut(),
                mock_env(),
                message_info(sender, &[]),
                ExecuteMsg::FreezeChains {
                    chains: test_case.clone(),
                }
                .into(),
            );
            assert!(result_check(&res));
        }

        let chains = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::Chains {
                start_after: None,
                limit: None,
            },
        )
        .unwrap()
        .then(|chains| from_json::<Vec<ChainEndpoint>>(&chains))
        .unwrap();

        for chain in chains.iter() {
            assert!(chain.incoming_frozen() && chain.outgoing_frozen())
        }

        // try sender without permission
        let permission_control: Vec<(Addr, Check)> = vec![
            (api.addr_make(UNAUTHORIZED_ADDRESS), Result::is_err),
            (api.addr_make(GOVERNANCE_ADDRESS), Result::is_ok),
            (api.addr_make(ADMIN_ADDRESS), Result::is_ok),
        ];

        for permission_case in permission_control.iter() {
            let (sender, result_check) = permission_case;
            let res = execute(
                deps.as_mut(),
                mock_env(),
                message_info(sender, &[]),
                ExecuteMsg::UnfreezeChains {
                    chains: HashMap::from([
                        (eth.chain_name.clone(), GatewayDirection::Bidirectional),
                        (polygon.chain_name.clone(), GatewayDirection::Bidirectional),
                    ]),
                }
                .into(),
            );
            assert!(result_check(&res));
        }

        let chains = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::Chains {
                start_after: None,
                limit: None,
            },
        )
        .unwrap()
        .then(|chains| from_json::<Vec<ChainEndpoint>>(&chains))
        .unwrap();

        for chain in chains.iter() {
            assert!(!chain.incoming_frozen() && !chain.outgoing_frozen())
        }
    }

    #[test]
    fn unfreeze_incoming() {
        let mut deps = setup();
        let api = deps.api;
        let eth = make_chain("ethereum");
        let polygon = make_chain("polygon");
        register_chain(deps.as_mut(), &eth);
        register_chain(deps.as_mut(), &polygon);

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::FreezeChains {
                chains: HashMap::from([(
                    polygon.chain_name.clone(),
                    GatewayDirection::Bidirectional,
                )]),
            }
            .into(),
        );
        assert!(res.is_ok());

        let nonce = &mut 0;

        // unfreeze incoming
        let _ = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::UnfreezeChains {
                chains: HashMap::from([(polygon.chain_name.clone(), GatewayDirection::Incoming)]),
            }
            .into(),
        )
        .unwrap();

        // can route from the chain
        let message = &generate_messages(&polygon, &eth, nonce, 1)[0];
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&polygon.gateway, &[]),
            ExecuteMsg::RouteMessages(vec![message.clone()]).into(),
        );
        assert!(res.is_ok());

        let message = &generate_messages(&eth, &polygon, nonce, 1)[0];
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&eth.gateway, &[]),
            ExecuteMsg::RouteMessages(vec![message.clone()]).into(),
        )
        .unwrap_err();
        // can't route to the chain
        assert_contract_err_string_contains(
            err,
            Error::ChainFrozen {
                chain: polygon.chain_name.clone(),
            },
        );
    }

    #[test]
    fn unfreeze_outgoing() {
        let mut deps = setup();
        let api = deps.api;
        let eth = make_chain("ethereum");
        let polygon = make_chain("polygon");
        register_chain(deps.as_mut(), &eth);
        register_chain(deps.as_mut(), &polygon);

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::FreezeChains {
                chains: HashMap::from([(
                    polygon.chain_name.clone(),
                    GatewayDirection::Bidirectional,
                )]),
            }
            .into(),
        );
        assert!(res.is_ok());

        let nonce = &mut 0;

        // unfreeze outgoing
        let _ = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::UnfreezeChains {
                chains: HashMap::from([(polygon.chain_name.clone(), GatewayDirection::Outgoing)]),
            }
            .into(),
        )
        .unwrap();

        // can't route from frozen chain
        let message = &generate_messages(&polygon, &eth, nonce, 1)[0];
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&polygon.gateway, &[]),
            ExecuteMsg::RouteMessages(vec![message.clone()]).into(),
        )
        .unwrap_err();
        assert_contract_err_string_contains(
            err,
            Error::ChainFrozen {
                chain: polygon.chain_name.clone(),
            },
        );

        // can route to the chain now
        let message = &generate_messages(&eth, &polygon, nonce, 1)[0];
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&eth.gateway, &[]),
            ExecuteMsg::RouteMessages(vec![message.clone()]).into(),
        );
        assert!(res.is_ok());
    }

    #[test]
    fn freeze_incoming_then_outgoing() {
        let mut deps = setup();
        let api = deps.api;
        let eth = make_chain("ethereum");
        let polygon = make_chain("polygon");
        register_chain(deps.as_mut(), &eth);
        register_chain(deps.as_mut(), &polygon);

        let _ = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::FreezeChains {
                chains: HashMap::from([(polygon.chain_name.clone(), GatewayDirection::Incoming)]),
            }
            .into(),
        )
        .unwrap();

        let _ = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::FreezeChains {
                chains: HashMap::from([(polygon.chain_name.clone(), GatewayDirection::Outgoing)]),
            }
            .into(),
        )
        .unwrap();

        let nonce = &mut 0;
        // can't route to frozen chain
        let message = &generate_messages(&eth, &polygon, nonce, 1)[0];
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&eth.gateway, &[]),
            ExecuteMsg::RouteMessages(vec![message.clone()]).into(),
        )
        .unwrap_err();
        assert_contract_err_string_contains(
            err,
            Error::ChainFrozen {
                chain: polygon.chain_name.clone(),
            },
        );

        // can't route from frozen chain
        let message = &generate_messages(&polygon, &eth, nonce, 1)[0];
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&polygon.gateway, &[]),
            ExecuteMsg::RouteMessages(vec![message.clone()]).into(),
        )
        .unwrap_err();
        assert_contract_err_string_contains(
            err,
            Error::ChainFrozen {
                chain: polygon.chain_name.clone(),
            },
        );
    }

    #[test]
    fn freeze_outgoing_then_incoming() {
        let mut deps = setup();
        let api = deps.api;
        let eth = make_chain("ethereum");
        let polygon = make_chain("polygon");
        register_chain(deps.as_mut(), &eth);
        register_chain(deps.as_mut(), &polygon);

        let _ = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::FreezeChains {
                chains: HashMap::from([(polygon.chain_name.clone(), GatewayDirection::Outgoing)]),
            }
            .into(),
        )
        .unwrap();

        let _ = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::FreezeChains {
                chains: HashMap::from([(polygon.chain_name.clone(), GatewayDirection::Incoming)]),
            }
            .into(),
        )
        .unwrap();

        let nonce = &mut 0;
        // can't route to frozen chain
        let message = &generate_messages(&eth, &polygon, nonce, 1)[0];
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&eth.gateway, &[]),
            ExecuteMsg::RouteMessages(vec![message.clone()]).into(),
        )
        .unwrap_err();
        assert_contract_err_string_contains(
            err,
            Error::ChainFrozen {
                chain: polygon.chain_name.clone(),
            },
        );

        // can't route from frozen chain
        let message = &generate_messages(&polygon, &eth, nonce, 1)[0];
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&polygon.gateway, &[]),
            ExecuteMsg::RouteMessages(vec![message.clone()]).into(),
        )
        .unwrap_err();
        assert_contract_err_string_contains(
            err,
            Error::ChainFrozen {
                chain: polygon.chain_name.clone(),
            },
        );
    }

    #[test]
    fn unfreeze_incoming_then_outgoing() {
        let mut deps = setup();
        let api = deps.api;
        let eth = make_chain("ethereum");
        let polygon = make_chain("polygon");
        register_chain(deps.as_mut(), &eth);
        register_chain(deps.as_mut(), &polygon);

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::FreezeChains {
                chains: HashMap::from([(
                    polygon.chain_name.clone(),
                    GatewayDirection::Bidirectional,
                )]),
            }
            .into(),
        );
        assert!(res.is_ok());

        // unfreeze incoming
        let _ = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::UnfreezeChains {
                chains: HashMap::from([(polygon.chain_name.clone(), GatewayDirection::Incoming)]),
            }
            .into(),
        )
        .unwrap();

        // unfreeze outgoing
        let _ = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::UnfreezeChains {
                chains: HashMap::from([(polygon.chain_name.clone(), GatewayDirection::Outgoing)]),
            }
            .into(),
        )
        .unwrap();

        // can route to the chain now
        let nonce = &mut 0;
        let message = &generate_messages(&eth, &polygon, nonce, 1)[0];
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&eth.gateway, &[]),
            ExecuteMsg::RouteMessages(vec![message.clone()]).into(),
        );
        assert!(res.is_ok());

        // can route from the chain
        let message = &generate_messages(&polygon, &eth, nonce, 1)[0];
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&polygon.gateway, &[]),
            ExecuteMsg::RouteMessages(vec![message.clone()]).into(),
        );
        assert!(res.is_ok());
    }

    #[test]
    fn unfreeze_outgoing_then_incoming() {
        let mut deps = setup();
        let api = deps.api;
        let eth = make_chain("ethereum");
        let polygon = make_chain("polygon");
        register_chain(deps.as_mut(), &eth);
        register_chain(deps.as_mut(), &polygon);

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::FreezeChains {
                chains: HashMap::from([(
                    polygon.chain_name.clone(),
                    GatewayDirection::Bidirectional,
                )]),
            }
            .into(),
        );
        assert!(res.is_ok());

        // unfreeze outgoing
        let _ = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::UnfreezeChains {
                chains: HashMap::from([(polygon.chain_name.clone(), GatewayDirection::Outgoing)]),
            }
            .into(),
        )
        .unwrap();

        // unfreeze incoming
        let _ = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::UnfreezeChains {
                chains: HashMap::from([(polygon.chain_name.clone(), GatewayDirection::Incoming)]),
            }
            .into(),
        )
        .unwrap();

        // can route to the chain now
        let nonce = &mut 0;
        let message = &generate_messages(&eth, &polygon, nonce, 1)[0];
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&eth.gateway, &[]),
            ExecuteMsg::RouteMessages(vec![message.clone()]).into(),
        );
        assert!(res.is_ok());

        // can route from the chain
        let message = &generate_messages(&polygon, &eth, nonce, 1)[0];
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&polygon.gateway, &[]),
            ExecuteMsg::RouteMessages(vec![message.clone()]).into(),
        );
        assert!(res.is_ok());
    }

    #[test]
    fn unfreeze_nothing() {
        let mut deps = setup();
        let api = deps.api;
        let eth = make_chain("ethereum");
        let polygon = make_chain("polygon");
        register_chain(deps.as_mut(), &eth);
        register_chain(deps.as_mut(), &polygon);

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::FreezeChains {
                chains: HashMap::from([(
                    polygon.chain_name.clone(),
                    GatewayDirection::Bidirectional,
                )]),
            }
            .into(),
        );
        assert!(res.is_ok());

        // unfreeze nothing
        let _ = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::UnfreezeChains {
                chains: HashMap::from([(polygon.chain_name.clone(), GatewayDirection::None)]),
            }
            .into(),
        )
        .unwrap();

        let nonce = &mut 0;
        let message = &generate_messages(&eth, &polygon, nonce, 1)[0];
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&eth.gateway, &[]),
            ExecuteMsg::RouteMessages(vec![message.clone()]).into(),
        )
        .unwrap_err();
        assert_contract_err_string_contains(
            err,
            Error::ChainFrozen {
                chain: polygon.chain_name.clone(),
            },
        );

        // can't route from frozen chain
        let message = &generate_messages(&polygon, &eth, nonce, 1)[0];
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&polygon.gateway, &[]),
            ExecuteMsg::RouteMessages(vec![message.clone()]).into(),
        )
        .unwrap_err();
        assert_contract_err_string_contains(
            err,
            Error::ChainFrozen {
                chain: polygon.chain_name.clone(),
            },
        );
    }

    #[test]
    fn disable_enable_router() {
        let mut deps = setup();
        let api = deps.api;
        let eth = make_chain("ethereum");
        let polygon = make_chain("polygon");
        register_chain(deps.as_mut(), &eth);
        register_chain(deps.as_mut(), &polygon);

        let nonce = &mut 0;
        let messages = &generate_messages(&eth, &polygon, nonce, 1);

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&eth.gateway, &[]),
            ExecuteMsg::RouteMessages(messages.clone()).into(),
        );

        assert!(res.is_ok());

        let _ = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::DisableRouting {}.into(),
        )
        .unwrap();

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&eth.gateway, &[]),
            ExecuteMsg::RouteMessages(messages.clone()).into(),
        );
        assert!(res.is_err());
        assert_contract_err_string_contains(res.unwrap_err(), Error::RoutingDisabled);

        let _ = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::EnableRouting {}.into(),
        )
        .unwrap();

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&eth.gateway, &[]),
            ExecuteMsg::RouteMessages(messages.clone()).into(),
        );

        assert!(res.is_ok());
    }

    #[test]
    fn ensure_correct_permissions_enable_disable_routing() {
        let mut deps = setup();
        let api = deps.api;
        assert!(execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(UNAUTHORIZED_ADDRESS), &[]),
            ExecuteMsg::EnableRouting {}.into(),
        )
        .is_err());
        assert!(execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::EnableRouting {}.into(),
        )
        .is_ok());
        assert!(execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(GOVERNANCE_ADDRESS), &[]),
            ExecuteMsg::EnableRouting {}.into(),
        )
        .is_ok());

        assert!(execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(UNAUTHORIZED_ADDRESS), &[]),
            ExecuteMsg::DisableRouting {}.into(),
        )
        .is_err());
        assert!(execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::DisableRouting {}.into(),
        )
        .is_ok());
        assert!(execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(GOVERNANCE_ADDRESS), &[]),
            ExecuteMsg::DisableRouting {}.into(),
        )
        .is_ok());
    }

    #[test]
    fn events_are_emitted_enable_disable_routing() {
        let mut deps = setup();
        let api = deps.api;
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::DisableRouting {}.into(),
        )
        .unwrap();

        assert!(res.events.len() == 1);
        assert!(res.events.contains(&Event::RoutingDisabled.into()));

        // don't emit event if already disabled
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::DisableRouting {}.into(),
        )
        .unwrap();

        assert!(res.events.is_empty());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::EnableRouting {}.into(),
        )
        .unwrap();

        assert!(res.events.len() == 1);
        assert!(res.events.contains(&Event::RoutingEnabled.into()));

        // don't emit event if already enabled
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsg::EnableRouting {}.into(),
        )
        .unwrap();

        assert!(res.events.is_empty());
    }

    #[test]
    fn is_enabled() {
        let mut deps = mock_dependencies();
        let is_enabled = |deps: Deps| {
            from_json::<bool>(query(deps, mock_env(), QueryMsg::IsEnabled).unwrap()).unwrap()
        };
        assert!(!is_enabled(deps.as_ref()));

        killswitch::init(deps.as_mut().storage, killswitch::State::Engaged).unwrap();
        assert!(!is_enabled(deps.as_ref()));
        killswitch::engage(deps.as_mut().storage, Event::RoutingDisabled).unwrap();
        assert!(!is_enabled(deps.as_ref()));
        killswitch::disengage(deps.as_mut().storage, Event::RoutingEnabled).unwrap();
        assert!(is_enabled(deps.as_ref()));
    }

    #[test]
    fn nexus_can_route_messages() {
        let mut deps = setup();
        let api = deps.api;
        let eth = make_chain("ethereum");
        let polygon = make_chain("polygon");

        register_chain(deps.as_mut(), &eth);
        register_chain(deps.as_mut(), &polygon);

        assert!(execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(AXELARNET_GATEWAY_ADDRESS), &[]),
            ExecuteMsg::RouteMessages(generate_messages(&eth, &polygon, &mut 0, 10)).into(),
        )
        .is_ok());
    }

    #[test]
    fn chain_info_fails_on_unregistered_chain() {
        let deps = setup();
        let unregistered_chain: ChainName = "unregistered".parse().unwrap();

        // Ensure that the error message doesn't change unexpectedly since the relayer depends on it
        let err = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::ChainInfo(unregistered_chain),
        )
        .unwrap_err();
        goldie::assert!(err.to_string());
    }

    #[test]
    fn direct_msgs_succeeds_nexus_routing_check() {
        let mut deps = setup();
        let api = deps.api;
        let eth = make_chain("ethereum");
        let polygon = make_chain("polygon");

        register_chain(deps.as_mut(), &eth);
        register_chain(deps.as_mut(), &polygon);

        assert!(execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(AXELARNET_GATEWAY_ADDRESS), &[]),
            ExecuteMsgFromProxy::Direct(ExecuteMsg::RouteMessages(generate_messages(
                &eth, &polygon, &mut 0, 10
            ))),
        )
        .is_ok());
    }

    #[test]
    fn only_coordinator_executes_coordinator_endpoint_succeeds() {
        let mut deps = setup();
        let api = deps.api;

        let polygon = make_chain("polygon");

        assert!(execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(COORDINATOR_ADDRESS), &[]),
            ExecuteMsgFromProxy::Relay {
                original_sender: api.addr_make(GOVERNANCE_ADDRESS),
                msg: router_api::msg::ExecuteMsg::RegisterChain {
                    chain: polygon.chain_name.clone(),
                    gateway_address: polygon.gateway.to_string().try_into().unwrap(),
                    msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
                },
            },
        )
        .is_ok());
    }

    #[test]
    fn only_coordinator_executes_coordinator_endpoint_fails() {
        let mut deps = setup();
        let api = deps.api;

        let polygon = make_chain("polygon");

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN_ADDRESS), &[]),
            ExecuteMsgFromProxy::Relay {
                original_sender: api.addr_make(GOVERNANCE_ADDRESS),
                msg: router_api::msg::ExecuteMsg::RegisterChain {
                    chain: polygon.chain_name.clone(),
                    gateway_address: polygon.gateway.to_string().try_into().unwrap(),
                    msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
                },
            },
        );

        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains(&axelar_wasm_std::permission_control::Error::Unauthorized.to_string()));
    }

    #[test]
    fn coordinator_endpoint_only_allows_register_msg() {
        let mut deps = setup();
        let api = deps.api;

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(COORDINATOR_ADDRESS), &[]),
            ExecuteMsgFromProxy::Relay {
                original_sender: api.addr_make(GOVERNANCE_ADDRESS),
                msg: ExecuteMsg::EnableRouting {},
            },
        );

        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains(&axelar_wasm_std::permission_control::Error::Unauthorized.to_string()));
    }
}
