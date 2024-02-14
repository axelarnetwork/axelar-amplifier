pub mod mock;
mod test_utils;

use std::str::FromStr;
use std::{collections::HashMap, vec};

use cosmwasm_std::{Addr, Uint128};
use cw_multi_test::{App, ContractWrapper, Executor};

use crate::test_utils::ConnectionRouterContract;
use connection_router::contract::*;
use connection_router::error::ContractError;
use connection_router::msg::{ExecuteMsg, InstantiateMsg};
use connection_router::state::{ChainName, CrossChainId, GatewayDirection, Message};
use integration_tests::contract::Contract;

struct TestConfig {
    app: App,
    admin_address: Addr,
    governance_address: Addr,
    connection_router: ConnectionRouterContract,
}

struct Chain {
    chain_name: ChainName,
    gateway: Addr,
}

fn setup() -> TestConfig {
    let mut app = App::default();

    let admin_address = Addr::unchecked("admin");
    let governance_address = Addr::unchecked("governance");
    let nexus_gateway = Addr::unchecked("nexus_gateway");

    let connection_router = ConnectionRouterContract::instantiate_contract(
        &mut app,
        admin_address.clone(),
        governance_address.clone(),
        nexus_gateway.clone(),
    );

    TestConfig {
        app,
        admin_address,
        governance_address,
        connection_router,
    }
}

fn make_chain(name: &str, config: &mut TestConfig) -> Chain {
    let gateway = mock::make_mock_gateway(&mut config.app);
    Chain {
        chain_name: name.parse().unwrap(),
        gateway,
    }
}

fn register_chain(config: &mut TestConfig, chain: &Chain) {
    config
        .connection_router
        .execute(
            &mut config.app,
            config.governance_address.clone(),
            &ExecuteMsg::RegisterChain {
                chain: chain.chain_name.clone(),
                gateway_address: chain.gateway.to_string(),
            },
        )
        .unwrap();
}

fn generate_messages(
    src_chain: &Chain,
    dest_chain: &Chain,
    nonce: &mut usize,
    count: usize,
) -> Vec<Message> {
    let mut msgs = vec![];
    for x in 0..count {
        *nonce = *nonce + 1;
        let id = format!("tx_id:{}", nonce);
        msgs.push(Message {
            cc_id: CrossChainId {
                id: id.parse().unwrap(),
                chain: src_chain.chain_name.clone(),
            },
            destination_address: "idc".parse().unwrap(),
            destination_chain: dest_chain.chain_name.clone(),
            source_address: "idc".parse().unwrap(),
            payload_hash: [x as u8; 32],
        })
    }
    msgs
}

// tests that each message is properly delivered
#[test]
fn route() {
    let mut config = setup();
    let eth = make_chain("ethereum", &mut config);
    let polygon = make_chain("polygon", &mut config);

    let _ = register_chain(&mut config, &eth);
    let _ = register_chain(&mut config, &polygon);

    let nonce: &mut usize = &mut 0;
    let messages = generate_messages(&eth, &polygon, nonce, 255);

    let _ = config
        .connection_router
        .execute(
            &mut config.app,
            eth.gateway.clone(),
            &ExecuteMsg::RouteMessages(messages.clone()),
        )
        .unwrap();

    let outgoing_messages = mock::get_gateway_messages(&mut config.app, polygon.gateway, &messages);

    assert_eq!(messages.len(), outgoing_messages.len());
    assert_eq!(messages, outgoing_messages);

    // try to route twice
    let res = config.connection_router.execute(
        &mut config.app,
        eth.gateway.clone(),
        &ExecuteMsg::RouteMessages(messages.clone()),
    );

    assert!(res.is_ok());
}
//
// #[test]
// fn wrong_source_chain() {
//     let mut config = setup();
//     let eth = make_chain("ethereum", &mut config);
//     let polygon = make_chain("polygon", &mut config);
//
//     register_chain(&mut config, &eth);
//     register_chain(&mut config, &polygon);
//
//     let msg = &generate_messages(&eth, &polygon, &mut 0, 1)[0];
//
//     let res = config
//         .app
//         .execute_contract(
//             polygon.gateway.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//             &[],
//         )
//         .unwrap_err();
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::WrongSourceChain).to_string()
//     );
// }
//
// #[test]
// fn multi_chain_route() {
//     let mut config = setup();
//     let chains = vec![
//         make_chain("ethereum", &mut config),
//         make_chain("polygon", &mut config),
//         make_chain("osmosis", &mut config),
//         make_chain("avalanche", &mut config),
//         make_chain("moonbeam", &mut config),
//     ];
//     for c in &chains {
//         register_chain(&mut config, c);
//     }
//
//     let nonce = &mut 0;
//     let mut all_msgs_by_dest = HashMap::new();
//     let mut all_msgs_by_src = HashMap::new();
//     for d in &chains {
//         let mut msgs = vec![];
//         for s in &chains {
//             let mut sending = generate_messages(&s, &d, nonce, 50);
//
//             all_msgs_by_src
//                 .entry(s.chain_name.to_string())
//                 .or_insert(vec![])
//                 .append(&mut sending);
//
//             msgs.append(&mut sending);
//         }
//         all_msgs_by_dest.insert(d.chain_name.to_string(), msgs);
//     }
//
//     for s in &chains {
//         let res = config.app.execute_contract(
//             s.gateway.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::RouteMessages(
//                 all_msgs_by_src
//                     .get_mut(&s.chain_name.to_string())
//                     .unwrap()
//                     .clone(),
//             ),
//             &[],
//         );
//         assert!(res.is_ok());
//     }
//
//     for d in &chains {
//         let expected = all_msgs_by_dest.get(&d.chain_name.to_string()).unwrap();
//
//         let actual = mock::get_gateway_messages(&mut config.app, d.gateway.clone(), expected);
//         assert_eq!(expected.len(), actual.len());
//         assert_eq!(expected, &actual);
//     }
// }
//
// #[test]
// fn authorization() {
//     let mut config = setup();
//
//     let chain = make_chain("ethereum", &mut config);
//
//     let res = config
//         .app
//         .execute_contract(
//             Addr::unchecked("random"),
//             config.contract_address.clone(),
//             &ExecuteMsg::RegisterChain {
//                 chain: chain.chain_name.clone(),
//                 gateway_address: chain.gateway.to_string(),
//             },
//             &[],
//         )
//         .unwrap_err();
//
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::Unauthorized).to_string()
//     );
//
//     let res = config
//         .app
//         .execute_contract(
//             config.admin_address.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::RegisterChain {
//                 chain: chain.chain_name.clone(),
//                 gateway_address: chain.gateway.to_string(),
//             },
//             &[],
//         )
//         .unwrap_err();
//
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::Unauthorized).to_string()
//     );
//
//     let res = config.app.execute_contract(
//         config.governance_address.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::RegisterChain {
//             chain: chain.chain_name.clone(),
//             gateway_address: chain.gateway.to_string(),
//         },
//         &[],
//     );
//     assert!(res.is_ok());
//
//     let res = config
//         .app
//         .execute_contract(
//             Addr::unchecked("random"),
//             config.contract_address.clone(),
//             &ExecuteMsg::FreezeChain {
//                 chain: chain.chain_name.clone(),
//                 direction: GatewayDirection::Bidirectional,
//             },
//             &[],
//         )
//         .unwrap_err();
//
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::Unauthorized).to_string()
//     );
//
//     let res = config
//         .app
//         .execute_contract(
//             config.governance_address.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::FreezeChain {
//                 chain: chain.chain_name.clone(),
//                 direction: GatewayDirection::Bidirectional,
//             },
//             &[],
//         )
//         .unwrap_err();
//
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::Unauthorized).to_string()
//     );
//
//     let res = config.app.execute_contract(
//         config.admin_address.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::FreezeChain {
//             chain: chain.chain_name.clone(),
//             direction: GatewayDirection::Bidirectional,
//         },
//         &[],
//     );
//     assert!(res.is_ok());
//
//     let res = config
//         .app
//         .execute_contract(
//             Addr::unchecked("random"),
//             config.contract_address.clone(),
//             &ExecuteMsg::FreezeChain {
//                 chain: chain.chain_name.clone(),
//                 direction: GatewayDirection::None,
//             },
//             &[],
//         )
//         .unwrap_err();
//
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::Unauthorized).to_string()
//     );
//
//     let res = config
//         .app
//         .execute_contract(
//             config.governance_address.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::FreezeChain {
//                 chain: chain.chain_name.clone(),
//                 direction: GatewayDirection::None,
//             },
//             &[],
//         )
//         .unwrap_err();
//
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::Unauthorized).to_string()
//     );
//
//     let res = config.app.execute_contract(
//         config.admin_address.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::FreezeChain {
//             chain: chain.chain_name.clone(),
//             direction: GatewayDirection::None,
//         },
//         &[],
//     );
//     assert!(res.is_ok());
//
//     let res = config
//         .app
//         .execute_contract(
//             Addr::unchecked("random"),
//             config.contract_address.clone(),
//             &ExecuteMsg::UpgradeGateway {
//                 chain: chain.chain_name.clone(),
//                 contract_address: Addr::unchecked("new gateway").to_string(),
//             },
//             &[],
//         )
//         .unwrap_err();
//
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::Unauthorized).to_string()
//     );
//
//     let res = config
//         .app
//         .execute_contract(
//             config.admin_address.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::UpgradeGateway {
//                 chain: chain.chain_name.clone(),
//                 contract_address: Addr::unchecked("new gateway").to_string(),
//             },
//             &[],
//         )
//         .unwrap_err();
//
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::Unauthorized).to_string()
//     );
//
//     let res = config.app.execute_contract(
//         config.governance_address.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::UpgradeGateway {
//             chain: chain.chain_name.clone(),
//             contract_address: Addr::unchecked("new gateway").to_string(),
//         },
//         &[],
//     );
//     assert!(res.is_ok());
// }
//
// #[test]
// fn upgrade_gateway_outgoing() {
//     let mut config = setup();
//     let eth = make_chain("ethereum", &mut config);
//     let polygon = make_chain("polygon", &mut config);
//
//     register_chain(&mut config, &eth);
//     register_chain(&mut config, &polygon);
//     let new_gateway = mock::make_mock_gateway(&mut config.app);
//
//     let _ = config
//         .app
//         .execute_contract(
//             config.governance_address.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::UpgradeGateway {
//                 chain: polygon.chain_name.clone(),
//                 contract_address: new_gateway.to_string(),
//             },
//             &[],
//         )
//         .unwrap();
//
//     let msg = &generate_messages(&eth, &polygon, &mut 0, 1)[0];
//     let _ = config
//         .app
//         .execute_contract(
//             eth.gateway.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//             &[],
//         )
//         .unwrap();
//
//     let msgs = mock::get_gateway_messages(&mut config.app, new_gateway, &vec![msg.clone()]);
//     assert_eq!(msgs.len(), 1);
//     assert_eq!(msg.clone(), msgs[0]);
//
//     let msgs = mock::get_gateway_messages(&mut config.app, polygon.gateway, &vec![msg.clone()]);
//     assert_eq!(msgs.len(), 0);
// }
//
// #[test]
// fn upgrade_gateway_incoming() {
//     let mut config = setup();
//     let eth = make_chain("ethereum", &mut config);
//     let polygon = make_chain("polygon", &mut config);
//
//     register_chain(&mut config, &eth);
//     register_chain(&mut config, &polygon);
//     let new_gateway = mock::make_mock_gateway(&mut config.app);
//
//     let _ = config
//         .app
//         .execute_contract(
//             config.governance_address.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::UpgradeGateway {
//                 chain: polygon.chain_name.clone(),
//                 contract_address: new_gateway.to_string(),
//             },
//             &[],
//         )
//         .unwrap();
//
//     let msg = &generate_messages(&polygon, &eth, &mut 0, 1)[0];
//     let res = config
//         .app
//         .execute_contract(
//             polygon.gateway.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//             &[],
//         )
//         .unwrap_err();
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::GatewayNotRegistered).to_string()
//     );
//
//     let res = config.app.execute_contract(
//         new_gateway,
//         config.contract_address.clone(),
//         &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//         &[],
//     );
//     assert!(res.is_ok());
//     let msgs = mock::get_gateway_messages(&mut config.app, eth.gateway, &vec![msg.clone()]);
//     assert_eq!(msgs.len(), 1);
//     assert_eq!(msgs[0], msg.clone());
// }
//
// #[test]
// fn register_chain_test() {
//     let mut config = setup();
//     let eth = make_chain("ethereum", &mut config);
//     let polygon = make_chain("polygon", &mut config);
//
//     let msg = &generate_messages(&eth, &polygon, &mut 0, 1)[0];
//     let res = config
//         .app
//         .execute_contract(
//             eth.gateway.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//             &[],
//         )
//         .unwrap_err();
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::GatewayNotRegistered).to_string()
//     );
//
//     register_chain(&mut config, &eth);
//     register_chain(&mut config, &polygon);
//
//     let res = config.app.execute_contract(
//         eth.gateway.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//         &[],
//     );
//     assert!(res.is_ok());
// }
//
// #[test]
// fn chain_already_registered() {
//     let mut config = setup();
//     let eth = make_chain("ethereum", &mut config);
//     register_chain(&mut config, &eth);
//
//     let res = config
//         .app
//         .execute_contract(
//             config.governance_address.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::RegisterChain {
//                 chain: eth.chain_name,
//                 gateway_address: Addr::unchecked("new gateway").to_string(),
//             },
//             &[],
//         )
//         .unwrap_err();
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::ChainAlreadyExists).to_string()
//     );
//
//     // case insensitive
//     let res = config
//         .app
//         .execute_contract(
//             config.governance_address.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::RegisterChain {
//                 chain: ChainName::from_str("ETHEREUM").unwrap(),
//                 gateway_address: Addr::unchecked("new gateway").to_string(),
//             },
//             &[],
//         )
//         .unwrap_err();
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::ChainAlreadyExists).to_string()
//     );
// }
//
// #[test]
// fn invalid_chain_name() {
//     assert_eq!(
//         ChainName::from_str("bad:").unwrap_err().to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::InvalidChainName).to_string()
//     );
//
//     assert_eq!(
//         ChainName::from_str("").unwrap_err().to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::InvalidChainName).to_string()
//     );
// }
//
// #[test]
// fn gateway_already_registered() {
//     let mut config = setup();
//     let eth = make_chain("ethereum", &mut config);
//     let polygon = make_chain("polygon", &mut config);
//     register_chain(&mut config, &eth);
//     let res = config
//         .app
//         .execute_contract(
//             config.governance_address.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::RegisterChain {
//                 chain: polygon.chain_name.clone(),
//                 gateway_address: eth.gateway.to_string(),
//             },
//             &[],
//         )
//         .unwrap_err();
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::GatewayAlreadyRegistered).to_string()
//     );
//
//     register_chain(&mut config, &polygon);
//     let res = config
//         .app
//         .execute_contract(
//             config.governance_address.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::UpgradeGateway {
//                 chain: eth.chain_name,
//                 contract_address: polygon.gateway.to_string(),
//             },
//             &[],
//         )
//         .unwrap_err();
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::GatewayAlreadyRegistered).to_string()
//     );
// }
//
// #[test]
// fn freeze_incoming() {
//     let mut config = setup();
//     let eth = make_chain("ethereum", &mut config);
//     let polygon = make_chain("polygon", &mut config);
//     register_chain(&mut config, &eth);
//     register_chain(&mut config, &polygon);
//
//     let _ = config
//         .app
//         .execute_contract(
//             config.admin_address.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::FreezeChain {
//                 chain: polygon.chain_name.clone(),
//                 direction: GatewayDirection::Incoming,
//             },
//             &[],
//         )
//         .unwrap();
//
//     let msg = &generate_messages(&polygon, &eth, &mut 0, 1)[0];
//     // can't route from frozen incoming gateway
//     let res = config
//         .app
//         .execute_contract(
//             polygon.gateway.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//             &[],
//         )
//         .unwrap_err();
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::ChainFrozen {
//             chain: polygon.chain_name.clone()
//         })
//         .to_string()
//     );
//
//     let msg = &generate_messages(&eth, &polygon, &mut 0, 1)[0];
//     // can still route to chain
//     let res = config.app.execute_contract(
//         eth.gateway.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//         &[],
//     );
//     assert!(res.is_ok());
//     let msgs =
//         mock::get_gateway_messages(&mut config.app, polygon.gateway.clone(), &vec![msg.clone()]);
//     assert_eq!(&msgs[0], msg);
//
//     let res = config.app.execute_contract(
//         config.admin_address.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::UnfreezeChain {
//             chain: polygon.chain_name.clone(),
//             direction: GatewayDirection::Incoming,
//         },
//         &[],
//     );
//     assert!(res.is_ok());
//
//     let msg = &generate_messages(&polygon, &eth, &mut 0, 1)[0];
//     let res = config.app.execute_contract(
//         polygon.gateway.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//         &[],
//     );
//     assert!(res.is_ok());
// }
//
// #[test]
// fn freeze_outgoing() {
//     let mut config = setup();
//     let eth = make_chain("ethereum", &mut config);
//     let polygon = make_chain("polygon", &mut config);
//     register_chain(&mut config, &eth);
//     register_chain(&mut config, &polygon);
//
//     // freeze outgoing
//     let res = config.app.execute_contract(
//         config.admin_address.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::FreezeChain {
//             chain: polygon.chain_name.clone(),
//             direction: GatewayDirection::Outgoing,
//         },
//         &[],
//     );
//     assert!(res.is_ok());
//
//     // can still send to the chain, messages will queue up
//     let msg = &generate_messages(&eth, &polygon, &mut 0, 1)[0];
//     let res = config
//         .app
//         .execute_contract(
//             eth.gateway.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//             &[],
//         )
//         .unwrap_err();
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::ChainFrozen {
//             chain: polygon.chain_name.clone()
//         })
//         .to_string()
//     );
//
//     let res = config.app.execute_contract(
//         config.admin_address.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::UnfreezeChain {
//             chain: polygon.chain_name.clone(),
//             direction: GatewayDirection::Outgoing,
//         },
//         &[],
//     );
//     assert!(res.is_ok());
//
//     let res = config.app.execute_contract(
//         eth.gateway.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//         &[],
//     );
//     assert!(res.is_ok());
//     let msgs = mock::get_gateway_messages(&mut config.app, polygon.gateway, &vec![msg.clone()]);
//     assert_eq!(msgs.len(), 1);
//     assert_eq!(msgs[0], msg.clone());
// }
//
// #[test]
// fn freeze_chain() {
//     let mut config = setup();
//     let eth = make_chain("ethereum", &mut config);
//     let polygon = make_chain("polygon", &mut config);
//     register_chain(&mut config, &eth);
//     register_chain(&mut config, &polygon);
//
//     let nonce = &mut 0;
//     // route a message first
//     let routed_msg = &generate_messages(&eth, &polygon, nonce, 1)[0];
//     let _ = config
//         .app
//         .execute_contract(
//             eth.gateway.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::RouteMessages(vec![routed_msg.clone()]),
//             &[],
//         )
//         .unwrap();
//
//     let res = config.app.execute_contract(
//         config.admin_address.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::FreezeChain {
//             chain: polygon.chain_name.clone(),
//             direction: GatewayDirection::Bidirectional,
//         },
//         &[],
//     );
//     assert!(res.is_ok());
//
//     let msg = &generate_messages(&eth, &polygon, nonce, 1)[0];
//     let res = config
//         .app
//         .execute_contract(
//             eth.gateway.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//             &[],
//         )
//         .unwrap_err();
//     // can't route to frozen chain
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::ChainFrozen {
//             chain: polygon.chain_name.clone()
//         })
//         .to_string()
//     );
//
//     // can't route from frozen chain
//     let msg = &generate_messages(&polygon, &eth, nonce, 1)[0];
//     let res = config
//         .app
//         .execute_contract(
//             polygon.gateway.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//             &[],
//         )
//         .unwrap_err();
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::ChainFrozen {
//             chain: polygon.chain_name.clone()
//         })
//         .to_string()
//     );
//
//     // unfreeze and test that everything works correctly
//     let _ = config
//         .app
//         .execute_contract(
//             config.admin_address.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::UnfreezeChain {
//                 chain: polygon.chain_name.clone(),
//                 direction: GatewayDirection::Bidirectional,
//             },
//             &[],
//         )
//         .unwrap();
//
//     // routed message should have been preserved
//     let msgs_ret = mock::get_gateway_messages(
//         &mut config.app,
//         polygon.gateway.clone(),
//         &vec![routed_msg.clone()],
//     );
//     assert_eq!(1, msgs_ret.len());
//     assert_eq!(routed_msg.clone(), msgs_ret[0]);
//
//     // can route to the chain now
//     let msg = &generate_messages(&eth, &polygon, nonce, 1)[0];
//     let res = config.app.execute_contract(
//         eth.gateway.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//         &[],
//     );
//     assert!(res.is_ok());
//
//     // can route from the chain
//     let msg = &generate_messages(&polygon, &eth, nonce, 1)[0];
//     let res = config.app.execute_contract(
//         polygon.gateway.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//         &[],
//     );
//     assert!(res.is_ok());
// }
//
// #[test]
// fn unfreeze_incoming() {
//     let mut config = setup();
//     let eth = make_chain("ethereum", &mut config);
//     let polygon = make_chain("polygon", &mut config);
//     register_chain(&mut config, &eth);
//     register_chain(&mut config, &polygon);
//
//     let res = config.app.execute_contract(
//         config.admin_address.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::FreezeChain {
//             chain: polygon.chain_name.clone(),
//             direction: GatewayDirection::Bidirectional,
//         },
//         &[],
//     );
//     assert!(res.is_ok());
//
//     let nonce = &mut 0;
//
//     // unfreeze incoming
//     let _ = config
//         .app
//         .execute_contract(
//             config.admin_address.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::UnfreezeChain {
//                 chain: polygon.chain_name.clone(),
//                 direction: GatewayDirection::Incoming,
//             },
//             &[],
//         )
//         .unwrap();
//
//     // can route from the chain
//     let msg = &generate_messages(&polygon, &eth, nonce, 1)[0];
//     let res = config.app.execute_contract(
//         polygon.gateway.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//         &[],
//     );
//     assert!(res.is_ok());
//
//     let msg = &generate_messages(&eth, &polygon, nonce, 1)[0];
//     let res = config
//         .app
//         .execute_contract(
//             eth.gateway.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//             &[],
//         )
//         .unwrap_err();
//     // can't route to the chain
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::ChainFrozen {
//             chain: polygon.chain_name.clone()
//         })
//         .to_string()
//     );
// }
//
// #[test]
// fn unfreeze_outgoing() {
//     let mut config = setup();
//     let eth = make_chain("ethereum", &mut config);
//     let polygon = make_chain("polygon", &mut config);
//     register_chain(&mut config, &eth);
//     register_chain(&mut config, &polygon);
//
//     let res = config.app.execute_contract(
//         config.admin_address.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::FreezeChain {
//             chain: polygon.chain_name.clone(),
//             direction: GatewayDirection::Bidirectional,
//         },
//         &[],
//     );
//     assert!(res.is_ok());
//
//     let nonce = &mut 0;
//
//     // unfreeze outgoing
//     let _ = config
//         .app
//         .execute_contract(
//             config.admin_address.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::UnfreezeChain {
//                 chain: polygon.chain_name.clone(),
//                 direction: GatewayDirection::Outgoing,
//             },
//             &[],
//         )
//         .unwrap();
//
//     // can't route from frozen chain
//     let msg = &generate_messages(&polygon, &eth, nonce, 1)[0];
//     let res = config
//         .app
//         .execute_contract(
//             polygon.gateway.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//             &[],
//         )
//         .unwrap_err();
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::ChainFrozen {
//             chain: polygon.chain_name.clone()
//         })
//         .to_string()
//     );
//
//     // can route to the chain now
//     let msg = &generate_messages(&eth, &polygon, nonce, 1)[0];
//     let res = config.app.execute_contract(
//         eth.gateway.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//         &[],
//     );
//     assert!(res.is_ok());
// }
//
// #[test]
// fn freeze_incoming_then_outgoing() {
//     let mut config = setup();
//     let eth = make_chain("ethereum", &mut config);
//     let polygon = make_chain("polygon", &mut config);
//     register_chain(&mut config, &eth);
//     register_chain(&mut config, &polygon);
//
//     let _ = config
//         .app
//         .execute_contract(
//             config.admin_address.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::FreezeChain {
//                 chain: polygon.chain_name.clone(),
//                 direction: GatewayDirection::Incoming,
//             },
//             &[],
//         )
//         .unwrap();
//
//     let _ = config
//         .app
//         .execute_contract(
//             config.admin_address.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::FreezeChain {
//                 chain: polygon.chain_name.clone(),
//                 direction: GatewayDirection::Outgoing,
//             },
//             &[],
//         )
//         .unwrap();
//
//     let nonce = &mut 0;
//     let msg = &generate_messages(&eth, &polygon, nonce, 1)[0];
//     let res = config
//         .app
//         .execute_contract(
//             eth.gateway.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//             &[],
//         )
//         .unwrap_err();
//     // can't route to frozen chain
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::ChainFrozen {
//             chain: polygon.chain_name.clone()
//         })
//         .to_string()
//     );
//
//     // can't route from frozen chain
//     let msg = &generate_messages(&polygon, &eth, nonce, 1)[0];
//     let res = config
//         .app
//         .execute_contract(
//             polygon.gateway.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//             &[],
//         )
//         .unwrap_err();
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::ChainFrozen {
//             chain: polygon.chain_name.clone()
//         })
//         .to_string()
//     );
// }
//
// #[test]
// fn freeze_outgoing_then_incoming() {
//     let mut config = setup();
//     let eth = make_chain("ethereum", &mut config);
//     let polygon = make_chain("polygon", &mut config);
//     register_chain(&mut config, &eth);
//     register_chain(&mut config, &polygon);
//
//     let _ = config
//         .app
//         .execute_contract(
//             config.admin_address.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::FreezeChain {
//                 chain: polygon.chain_name.clone(),
//                 direction: GatewayDirection::Outgoing,
//             },
//             &[],
//         )
//         .unwrap();
//
//     let _ = config
//         .app
//         .execute_contract(
//             config.admin_address.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::FreezeChain {
//                 chain: polygon.chain_name.clone(),
//                 direction: GatewayDirection::Incoming,
//             },
//             &[],
//         )
//         .unwrap();
//
//     let nonce = &mut 0;
//     let msg = &generate_messages(&eth, &polygon, nonce, 1)[0];
//     let res = config
//         .app
//         .execute_contract(
//             eth.gateway.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//             &[],
//         )
//         .unwrap_err();
//     // can't route to frozen chain
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::ChainFrozen {
//             chain: polygon.chain_name.clone()
//         })
//         .to_string()
//     );
//
//     // can't route from frozen chain
//     let msg = &generate_messages(&polygon, &eth, nonce, 1)[0];
//     let res = config
//         .app
//         .execute_contract(
//             polygon.gateway.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//             &[],
//         )
//         .unwrap_err();
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::ChainFrozen {
//             chain: polygon.chain_name.clone()
//         })
//         .to_string()
//     );
// }
//
// #[test]
// fn unfreeze_incoming_then_outgoing() {
//     let mut config = setup();
//     let eth = make_chain("ethereum", &mut config);
//     let polygon = make_chain("polygon", &mut config);
//     register_chain(&mut config, &eth);
//     register_chain(&mut config, &polygon);
//
//     let res = config.app.execute_contract(
//         config.admin_address.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::FreezeChain {
//             chain: polygon.chain_name.clone(),
//             direction: GatewayDirection::Bidirectional,
//         },
//         &[],
//     );
//     assert!(res.is_ok());
//
//     // unfreeze incoming
//     let _ = config
//         .app
//         .execute_contract(
//             config.admin_address.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::UnfreezeChain {
//                 chain: polygon.chain_name.clone(),
//                 direction: GatewayDirection::Incoming,
//             },
//             &[],
//         )
//         .unwrap();
//
//     // unfreeze outgoing
//     let _ = config
//         .app
//         .execute_contract(
//             config.admin_address.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::UnfreezeChain {
//                 chain: polygon.chain_name.clone(),
//                 direction: GatewayDirection::Outgoing,
//             },
//             &[],
//         )
//         .unwrap();
//
//     // can route to the chain now
//     let nonce = &mut 0;
//     let msg = &generate_messages(&eth, &polygon, nonce, 1)[0];
//     let res = config.app.execute_contract(
//         eth.gateway.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//         &[],
//     );
//     assert!(res.is_ok());
//
//     // can route from the chain
//     let msg = &generate_messages(&polygon, &eth, nonce, 1)[0];
//     let res = config.app.execute_contract(
//         polygon.gateway.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//         &[],
//     );
//     assert!(res.is_ok());
// }
//
// #[test]
// fn unfreeze_outgoing_then_incoming() {
//     let mut config = setup();
//     let eth = make_chain("ethereum", &mut config);
//     let polygon = make_chain("polygon", &mut config);
//     register_chain(&mut config, &eth);
//     register_chain(&mut config, &polygon);
//
//     let res = config.app.execute_contract(
//         config.admin_address.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::FreezeChain {
//             chain: polygon.chain_name.clone(),
//             direction: GatewayDirection::Bidirectional,
//         },
//         &[],
//     );
//     assert!(res.is_ok());
//
//     // unfreeze outgoing
//     let _ = config
//         .app
//         .execute_contract(
//             config.admin_address.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::UnfreezeChain {
//                 chain: polygon.chain_name.clone(),
//                 direction: GatewayDirection::Outgoing,
//             },
//             &[],
//         )
//         .unwrap();
//
//     // unfreeze incoming
//     let _ = config
//         .app
//         .execute_contract(
//             config.admin_address.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::UnfreezeChain {
//                 chain: polygon.chain_name.clone(),
//                 direction: GatewayDirection::Incoming,
//             },
//             &[],
//         )
//         .unwrap();
//
//     // can route to the chain now
//     let nonce = &mut 0;
//     let msg = &generate_messages(&eth, &polygon, nonce, 1)[0];
//     let res = config.app.execute_contract(
//         eth.gateway.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//         &[],
//     );
//     assert!(res.is_ok());
//
//     // can route from the chain
//     let msg = &generate_messages(&polygon, &eth, nonce, 1)[0];
//     let res = config.app.execute_contract(
//         polygon.gateway.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//         &[],
//     );
//     assert!(res.is_ok());
// }
//
// #[test]
// fn unfreeze_nothing() {
//     let mut config = setup();
//     let eth = make_chain("ethereum", &mut config);
//     let polygon = make_chain("polygon", &mut config);
//     register_chain(&mut config, &eth);
//     register_chain(&mut config, &polygon);
//
//     let res = config.app.execute_contract(
//         config.admin_address.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::FreezeChain {
//             chain: polygon.chain_name.clone(),
//             direction: GatewayDirection::Bidirectional,
//         },
//         &[],
//     );
//     assert!(res.is_ok());
//
//     // unfreeze nothing
//     let _ = config
//         .app
//         .execute_contract(
//             config.admin_address.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::UnfreezeChain {
//                 chain: polygon.chain_name.clone(),
//                 direction: GatewayDirection::None,
//             },
//             &[],
//         )
//         .unwrap();
//
//     let nonce = &mut 0;
//     let msg = &generate_messages(&eth, &polygon, nonce, 1)[0];
//     let res = config
//         .app
//         .execute_contract(
//             eth.gateway.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//             &[],
//         )
//         .unwrap_err();
//     // can't route to frozen chain
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::ChainFrozen {
//             chain: polygon.chain_name.clone()
//         })
//         .to_string()
//     );
//
//     // can't route from frozen chain
//     let msg = &generate_messages(&polygon, &eth, nonce, 1)[0];
//     let res = config
//         .app
//         .execute_contract(
//             polygon.gateway.clone(),
//             config.contract_address.clone(),
//             &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//             &[],
//         )
//         .unwrap_err();
//     assert_eq!(
//         res.downcast::<axelar_wasm_std::ContractError>()
//             .unwrap()
//             .to_string(),
//         axelar_wasm_std::ContractError::from(ContractError::ChainFrozen {
//             chain: polygon.chain_name.clone()
//         })
//         .to_string()
//     );
// }
//
// #[test]
// fn bad_gateway() {
//     let mut config = setup();
//     let eth = make_chain("ethereum", &mut config);
//     let polygon = make_chain("polygon", &mut config);
//
//     register_chain(&mut config, &eth);
//     register_chain(&mut config, &polygon);
//
//     let res = config.app.execute_contract(
//         config.governance_address.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::UpgradeGateway {
//             chain: polygon.chain_name.clone(),
//             contract_address: Addr::unchecked("some random address").to_string(), // gateway address does not implement required interface
//         },
//         &[],
//     );
//
//     assert!(res.is_ok());
//
//     let nonce: &mut usize = &mut 0;
//     let msg = &generate_messages(&eth, &polygon, nonce, 1)[0];
//
//     let res = config.app.execute_contract(
//         eth.gateway.clone(),
//         config.contract_address.clone(),
//         &ExecuteMsg::RouteMessages(vec![msg.clone()]),
//         &[],
//     );
//     assert!(res.is_err());
// }
