use axelar_wasm_std::utils::TryMapExt;
use axelar_wasm_std::{FnExt, VerificationStatus};
use connection_router_api::{CrossChainId, Message};
use cosmwasm_std::WasmMsg;
use error_stack::{Result, ResultExt};
use std::collections::HashMap;

use crate::msg::{ExecuteMsg, QueryMsg};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("could not query the verifier contract")]
    QueryVerifier,
}

pub struct Client<'a> {
    pub client: client::Client<'a, ExecuteMsg, QueryMsg>,
}

impl<'a> Client<'a> {
    pub fn verify_messages(&self, msgs: Vec<Message>) -> Option<WasmMsg> {
        ignore_empty(msgs).map(|msgs| {
            self.client
                .execute(&ExecuteMsg::VerifyMessages { messages: msgs })
        })
    }

    pub fn messages_status(
        &self,
        msgs: Vec<Message>,
    ) -> Result<impl Iterator<Item = (Message, VerificationStatus)>, Error> {
        ignore_empty(msgs.clone())
            .try_map(|msgs| self.query_messages_status(msgs))?
            .map(|status_by_id| ids_to_msgs(status_by_id, msgs))
            .into_iter()
            .flatten()
            .then(Ok)
    }

    fn query_messages_status(
        &self,
        msgs: Vec<Message>,
    ) -> Result<HashMap<CrossChainId, VerificationStatus>, Error> {
        self.client
            .query::<Vec<(CrossChainId, VerificationStatus)>>(&QueryMsg::GetMessagesStatus {
                messages: msgs,
            })
            .change_context(Error::QueryVerifier)?
            .into_iter()
            .collect::<HashMap<_, _>>()
            .then(Ok)
    }
}

// TODO: unify across contract clients
fn ignore_empty(msgs: Vec<Message>) -> Option<Vec<Message>> {
    if msgs.is_empty() {
        None
    } else {
        Some(msgs)
    }
}

fn ids_to_msgs(
    status_by_id: HashMap<CrossChainId, VerificationStatus>,
    msgs: Vec<Message>,
) -> impl Iterator<Item = (Message, VerificationStatus)> {
    msgs.into_iter().map(move |msg| {
        let status = status_by_id
            .get(&msg.cc_id)
            .copied()
            .unwrap_or(VerificationStatus::None);
        (msg, status)
    })
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info, MockQuerier};
    use cosmwasm_std::{from_json, to_json_binary, Addr, DepsMut, QuerierWrapper, WasmQuery};
    use std::str::FromStr;

    use axelar_wasm_std::VerificationStatus;
    use connection_router_api::{CrossChainId, CHAIN_NAME_DELIMITER};

    use crate::contract::{instantiate, query};
    use crate::msg::InstantiateMsg;

    use super::*;

    #[test]
    fn query_messages_status_returns_empty_statuses() {
        let addr = "aggregate-verifier";

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart { contract_addr, msg } if contract_addr == addr => {
                let mut deps = mock_dependencies();
                instantiate_contract(deps.as_mut(), Addr::unchecked("verifier"));

                deps.querier.update_wasm(|_| {
                    let res: Vec<(CrossChainId, VerificationStatus)> = vec![];
                    Ok(to_json_binary(&res).into()).into()
                });

                let msg = from_json::<QueryMsg>(msg.as_slice()).unwrap();
                Ok(query(deps.as_ref(), mock_env(), msg).into()).into()
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        let client = Client {
            client: client::Client::new(QuerierWrapper::new(&querier), Addr::unchecked(addr)),
        };

        assert!(client.query_messages_status(vec![]).unwrap().is_empty());
    }

    #[test]
    fn query_messages_status_returns_some_statuses() {
        let addr = "aggregate-verifier";
        let msg_1 = Message {
            cc_id: CrossChainId::from_str(format!("eth{}0x1234", CHAIN_NAME_DELIMITER).as_str())
                .unwrap(),
            source_address: "0x1234".parse().unwrap(),
            destination_address: "0x5678".parse().unwrap(),
            destination_chain: "eth".parse().unwrap(),
            payload_hash: [0; 32],
        };
        let msg_2 = Message {
            cc_id: CrossChainId::from_str(format!("eth{}0x4321", CHAIN_NAME_DELIMITER).as_str())
                .unwrap(),
            source_address: "0x4321".parse().unwrap(),
            destination_address: "0x8765".parse().unwrap(),
            destination_chain: "eth".parse().unwrap(),
            payload_hash: [0; 32],
        };

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart { contract_addr, msg } if contract_addr == addr => {
                let mut deps = mock_dependencies();
                instantiate_contract(deps.as_mut(), Addr::unchecked("verifier"));

                deps.querier.update_wasm(|_| {
                    let res: Vec<(CrossChainId, VerificationStatus)> = vec![
                        (
                            CrossChainId::from_str(
                                format!("eth{}0x1234", CHAIN_NAME_DELIMITER).as_str(),
                            )
                            .unwrap(),
                            VerificationStatus::SucceededOnChain,
                        ),
                        (
                            CrossChainId::from_str(
                                format!("eth{}0x4321", CHAIN_NAME_DELIMITER).as_str(),
                            )
                            .unwrap(),
                            VerificationStatus::FailedOnChain,
                        ),
                    ];
                    Ok(to_json_binary(&res).into()).into()
                });

                let msg = from_json::<QueryMsg>(msg.as_slice()).unwrap();
                Ok(query(deps.as_ref(), mock_env(), msg).into()).into()
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        let client = Client {
            client: client::Client::new(QuerierWrapper::new(&querier), Addr::unchecked(addr)),
        };

        assert!(
            client
                .query_messages_status(vec![msg_1, msg_2])
                .unwrap()
                .len()
                == 2
        );
    }

    fn instantiate_contract(deps: DepsMut, verifier: Addr) {
        let env = mock_env();
        let info = mock_info("deployer", &[]);
        let msg = InstantiateMsg {
            verifier_address: verifier.into_string(),
        };

        instantiate(deps, env, info, msg).unwrap();
    }
}
