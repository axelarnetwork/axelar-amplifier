use axelar_wasm_std::error::accumulate_errs;
use cosmwasm_std::Deps;
use error_stack::Result;
use router_api::{CrossChainId, Message};

use crate::state::{self, ExecutableMessage};

pub fn contract_call_messages(
    deps: Deps,
    cc_ids: Vec<CrossChainId>,
) -> Result<Vec<Message>, state::Error> {
    cc_ids
        .into_iter()
        .map(|cc_id| state::load_contract_call_msg(deps.storage, &cc_id))
        .fold(Ok(vec![]), accumulate_errs)
}

pub fn executable_messages(
    deps: Deps,
    cc_ids: Vec<CrossChainId>,
) -> Result<Vec<ExecutableMessage>, state::Error> {
    cc_ids
        .into_iter()
        .map(|cc_id| state::load_executable_msg(deps.storage, &cc_id))
        .fold(Ok(vec![]), accumulate_errs)
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