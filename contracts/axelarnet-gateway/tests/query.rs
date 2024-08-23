use axelarnet_gateway::msg::QueryMsg;
use axelarnet_gateway::{contract, ExecutableMessage};
use cosmwasm_std::testing::{mock_dependencies, mock_env, MockApi, MockQuerier, MockStorage};
use cosmwasm_std::{from_json, Deps, OwnedDeps};
use router_api::msg::ExecuteMsg as RouterExecuteMsg;
use router_api::{CrossChainId, Message};
use sha3::{Digest, Keccak256};

use crate::utils::messages::inspect_response_msg;
use crate::utils::params;

mod utils;

#[test]
fn query_routable_messages_gets_expected_messages() {
    let mut deps = mock_dependencies();

    utils::instantiate_contract(deps.as_mut()).unwrap();
    let mut expected = populate_routable_messages(&mut deps);

    expected.remove(3);
    let cc_ids = expected.iter().map(|msg| &msg.cc_id).cloned().collect();

    let result = query_routable_messages(deps.as_ref(), cc_ids);

    assert_eq!(result.unwrap(), expected);
}

#[test]
fn query_executable_messages_gets_expected_messages() {
    let mut deps = mock_dependencies();

    utils::instantiate_contract(deps.as_mut()).unwrap();
    let mut cc_ids = populate_executable_messages(&mut deps);
    cc_ids.remove(3);

    let result = query_executable_messages(deps.as_ref(), cc_ids);

    assert!(result.is_ok());
    goldie::assert_json!(result.unwrap());
}

fn query_routable_messages(deps: Deps, cc_ids: Vec<CrossChainId>) -> Result<Vec<Message>, ()> {
    from_json(
        contract::query(deps, mock_env(), QueryMsg::RoutableMessages { cc_ids }).map_err(|_| ())?,
    )
    .map_err(|_| ())
}

fn query_executable_messages(
    deps: Deps,
    cc_ids: Vec<CrossChainId>,
) -> Result<Vec<ExecutableMessage>, ()> {
    from_json(
        contract::query(deps, mock_env(), QueryMsg::ExecutableMessages { cc_ids })
            .map_err(|_| ())?,
    )
    .map_err(|_| ())
}

fn populate_routable_messages(
    deps: &mut OwnedDeps<MockStorage, MockApi, MockQuerier>,
) -> Vec<Message> {
    (0..10)
        .map(|i| {
            let response = utils::call_contract(
                deps.as_mut(),
                format!("destination-chain-{}", i).parse().unwrap(),
                format!("destination-address-{}", i).parse().unwrap(),
                vec![i].into(),
            )
            .unwrap();

            let RouterExecuteMsg::RouteMessages(mut msgs) = inspect_response_msg(response).unwrap()
            else {
                panic!("pattern must match")
            };

            msgs.pop().unwrap()
        })
        .collect()
}

fn populate_executable_messages(
    deps: &mut OwnedDeps<MockStorage, MockApi, MockQuerier>,
) -> Vec<CrossChainId> {
    let msgs: Vec<_> = (0..10)
        .map(|i| Message {
            cc_id: CrossChainId::new("source-chain", format!("hash-index-{}", i)).unwrap(),
            source_address: "source-address".parse().unwrap(),
            destination_chain: params::AXELARNET.parse().unwrap(),
            destination_address: "destination-address".parse().unwrap(),
            payload_hash: Keccak256::digest(vec![i]).into(),
        })
        .collect();

    utils::route_from_router(deps.as_mut(), msgs.clone()).unwrap();

    utils::execute_payload(deps.as_mut(), msgs[0].cc_id.clone(), vec![0].into()).unwrap();
    utils::execute_payload(deps.as_mut(), msgs[5].cc_id.clone(), vec![5].into()).unwrap();
    utils::execute_payload(deps.as_mut(), msgs[7].cc_id.clone(), vec![7].into()).unwrap();

    msgs.into_iter().map(|msg| msg.cc_id).collect()
}

//
// #[cfg(test)]
// mod tests {
//     use axelar_wasm_std::{err_contains, FnExt};
//     use cosmwasm_std::from_json;
//     use cosmwasm_std::testing::{mock_dependencies, mock_env};
//     use router_api::{CrossChainId, Message};
//     use serde::de::DeserializeOwned;
//
//     use super::*;
//     use crate::contract;
//     use crate::msg::QueryMsg;
//
//     const SOURCE_CHAIN: &str = "source-chain";
//     const DESTINATION_CHAIN: &str = "destination-chain";
//
//     fn dummy_message(id: &str) -> Message {
//         Message {
//             cc_id: CrossChainId::new(SOURCE_CHAIN, id).unwrap(),
//             source_address: "source-address".parse().unwrap(),
//             destination_chain: DESTINATION_CHAIN.parse().unwrap(),
//             destination_address: "destination-address".parse().unwrap(),
//             payload_hash: [0; 32],
//         }
//     }
//
//     // Query a msg and deserialize it. If the query fails, the error is returned
//     fn query<T: DeserializeOwned>(
//         deps: Deps,
//         msg: QueryMsg,
//     ) -> Result<T, axelar_wasm_std::error::ContractError> {
//         contract::query(deps, mock_env(), msg)?
//             .then(from_json::<T>)
//             .unwrap()
//             .then(Ok)
//     }
//
//     #[test]
//     fn query_sent_messages() {
//         let mut deps = mock_dependencies();
//
//         let message1 = dummy_message("message-1");
//         let message2 = dummy_message("message-2");
//         let message3 = dummy_message("message-3");
//
//         // Save messages
//         state::save_unique_contract_call_msg(
//             deps.as_mut().storage,
//             message1.cc_id.clone(),
//             &message1,
//         )
//         .unwrap();
//         state::save_unique_contract_call_msg(
//             deps.as_mut().storage,
//             message2.cc_id.clone(),
//             &message2,
//         )
//         .unwrap();
//
//         // Query existing messages
//         let result: Vec<Message> = query(
//             deps.as_ref(),
//             QueryMsg::ContractCallMessages {
//                 cc_ids: vec![message1.cc_id.clone(), message2.cc_id.clone()],
//             },
//         )
//         .unwrap();
//         assert_eq!(result, vec![message1, message2]);
//
//         // Query with non-existent message
//         let err = query::<Vec<Message>>(
//             deps.as_ref(),
//             QueryMsg::ContractCallMessages {
//                 cc_ids: vec![message3.cc_id],
//             },
//         )
//         .unwrap_err();
//         assert!(err_contains!(
//             err.report,
//             state::Error,
//             state::Error::MessageNotFound(..)
//         ));
//     }
//
//     #[test]
//     fn query_received_messages() {
//         let mut deps = mock_dependencies();
//
//         let message1 = dummy_message("message-1");
//         let message2 = dummy_message("message-2");
//         let message3 = dummy_message("message-3");
//
//         // Save messages
//         state::save_executable_msg(
//             deps.as_mut().storage,
//             message1.cc_id.clone(),
//             message1.clone(),
//         )
//         .unwrap();
//         state::save_executable_msg(
//             deps.as_mut().storage,
//             message2.cc_id.clone(),
//             message2.clone(),
//         )
//         .unwrap();
//
//         // Set message2 as executed
//         state::mark_msg_as_executed(deps.as_mut().storage, message2.cc_id.clone()).unwrap();
//
//         // Query existing messages
//         let result: Vec<ExecutableMessage> = query(
//             deps.as_ref(),
//             QueryMsg::ExecutableMessages {
//                 cc_ids: vec![message1.cc_id.clone(), message2.cc_id.clone()],
//             },
//         )
//         .unwrap();
//
//         assert_eq!(
//             result,
//             vec![
//                 ExecutableMessage {
//                     msg: message1,
//                     status: MessageStatus::Approved
//                 },
//                 ExecutableMessage {
//                     msg: message2,
//                     status: MessageStatus::Executed
//                 }
//             ]
//         );
//
//         // Query with non-existent message
//         let err = query::<Vec<ExecutableMessage>>(
//             deps.as_ref(),
//             QueryMsg::ExecutableMessages {
//                 cc_ids: vec![message3.cc_id],
//             },
//         )
//         .unwrap_err();
//         assert!(err_contains!(
//             err.report,
//             state::Error,
//             state::Error::MessageNotFound(..)
//         ));
//     }
// }
