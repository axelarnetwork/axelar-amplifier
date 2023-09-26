use std::collections::HashMap;

use cosmwasm_std::{to_binary, Addr, Response, WasmMsg};
use error_stack::{Result, ResultExt};
use itertools::Itertools;

use crate::error::ContractError;
use connection_router::state::{CrossChainId, NewMessage};

use crate::events::GatewayEvent;
use crate::state::Config;

pub struct Contract<Q, S>
where
    Q: FnMut(aggregate_verifier::msg::QueryMsg) -> Result<Vec<(CrossChainId, bool)>, ContractError>,
    S: FnMut(CrossChainId, &NewMessage) -> Result<(), ContractError>,
{
    pub config: Config,
    pub query_verifier: Q,
    pub store_msg: S,
}

impl<Q, S> Contract<Q, S>
where
    Q: FnMut(aggregate_verifier::msg::QueryMsg) -> Result<Vec<(CrossChainId, bool)>, ContractError>,
    S: FnMut(CrossChainId, &NewMessage) -> Result<(), ContractError>,
{
    pub fn verify_messages(&mut self, msgs: Vec<NewMessage>) -> Result<Response, ContractError> {
        // short circuit if there are no messages, there is no need to interact with the verifier so it saves gas
        if msgs.is_empty() {
            return Ok(Response::new());
        }

        ensure_unique_ids(&msgs)?;

        let (_, unverified) = self.partition_by_verified(msgs)?;

        if unverified.is_empty() {
            return Ok(Response::new());
        }

        Ok(Response::new().add_message(WasmMsg::Execute {
            contract_addr: self.config.verifier.to_string(),
            msg: to_binary(&aggregate_verifier::msg::ExecuteMsg::VerifyMessages {
                messages: unverified,
            })
            .change_context(ContractError::CreateVerifierExecuteMsg)?,
            funds: vec![],
        }))
    }

    pub fn route_messages(
        &mut self,
        sender: Addr,
        msgs: Vec<NewMessage>,
    ) -> Result<Response, ContractError> {
        if sender == self.config.router {
            self.route_outgoing_messages(msgs)
        } else {
            self.route_incoming_messages(msgs)
        }
    }

    fn route_outgoing_messages(
        &mut self,
        msgs: Vec<NewMessage>,
    ) -> Result<Response, ContractError> {
        for msg in msgs.iter() {
            (self.store_msg)(msg.cc_id.clone(), msg)?;
        }

        Ok(Response::new().add_events(
            msgs.into_iter()
                .map(|msg| GatewayEvent::MessageRouted { msg }.into()),
        ))
    }

    fn route_incoming_messages(
        &mut self,
        msgs: Vec<NewMessage>,
    ) -> Result<Response, ContractError> {
        ensure_unique_ids(&msgs)?;

        let (verified, unverified) = self.partition_by_verified(msgs)?;

        Ok(Response::new()
            .add_message(WasmMsg::Execute {
                contract_addr: self.config.router.to_string(),
                msg: to_binary(&connection_router::msg::ExecuteMsg::RouteMessages(
                    verified.clone(),
                ))
                .change_context(ContractError::CreateRouterExecuteMsg)?,
                funds: vec![],
            })
            .add_events(
                verified
                    .into_iter()
                    .map(|msg| GatewayEvent::MessageRouted { msg }.into()),
            )
            .add_events(
                unverified
                    .into_iter()
                    .map(|msg| GatewayEvent::MessageRoutingFailed { msg }.into()),
            ))
    }

    fn partition_by_verified(
        &mut self,
        msgs: Vec<NewMessage>,
    ) -> Result<(Vec<NewMessage>, Vec<NewMessage>), ContractError> {
        let query_response =
            (self.query_verifier)(aggregate_verifier::msg::QueryMsg::IsVerified {
                messages: msgs.to_vec(),
            })?;

        let is_verified = query_response.into_iter().collect::<HashMap<_, _>>();

        Ok(msgs
            .into_iter()
            .partition(|msg| -> bool { is_verified.get(&msg.cc_id).copied().unwrap_or(false) }))
    }
}

fn ensure_unique_ids(msgs: &[NewMessage]) -> Result<(), ContractError> {
    let duplicates: Vec<_> = msgs
        .iter()
        .map(|m| &m.cc_id)
        .duplicates()
        .map(|cc_id| cc_id.to_string())
        .collect();
    if !duplicates.is_empty() {
        return Err(ContractError::DuplicateMessageID)
            .attach_printable(duplicates.iter().join(", "));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::contract::execute::Contract;
    use crate::error::ContractError;
    use crate::state;
    use connection_router::state::{CrossChainId, NewMessage, ID_SEPARATOR};
    use cosmwasm_std::{Addr, CosmosMsg, SubMsg, WasmMsg};
    use error_stack::{bail, Result};
    use std::collections::HashMap;

    /// If there are messages with duplicate IDs, the gateway should fail
    #[test]
    fn verify_fail_duplicates() {
        let msg_store = HashMap::new();
        let mut msgs = generate_messages(10);
        // no messages are verified
        let is_verified = HashMap::new();
        let mut contract = create_contract(msg_store, is_verified);

        // duplicate some IDs
        msgs[5..]
            .iter_mut()
            .for_each(|msg| msg.cc_id.id = "same_id:000".parse().unwrap());

        let result = contract.verify_messages(msgs);
        assert!(result
            .is_err_and(|err| matches!(err.current_context(), ContractError::DuplicateMessageID)));
    }

    /// If all messages are verified, the gateway should not call the verifier
    #[test]
    fn verify_all_verified() {
        let msg_store = HashMap::new();
        let msgs = generate_messages(10);
        // mark all generated messages as verified
        let is_verified = msgs.iter().map(|msg| (msg.cc_id.clone(), true)).collect();
        let mut contract = create_contract(msg_store, is_verified);

        let inputs = vec![vec![], msgs[..1].to_vec(), msgs];
        for input in inputs {
            let result = contract.verify_messages(input);
            assert!(result.is_ok());
            assert_eq!(result.unwrap().messages.len(), 0);
        }
    }

    /// If none of the messages are verified, the gateway should tell the verifier to verify all
    #[test]
    fn verify_none_verified() {
        let msg_store = HashMap::new();
        let msgs = generate_messages(10);
        // no messages are verified
        let is_verified = HashMap::new();
        let mut contract = create_contract(msg_store, is_verified);

        let inputs = vec![msgs[..1].to_vec(), msgs];

        // expect: no error, all input messages get verified
        for input in inputs {
            let result = contract.verify_messages(input.clone());
            assert!(result.is_ok());
            assert_correct_messages_verified(
                result.unwrap().messages,
                &contract.config.verifier,
                &input,
            );
        }
    }

    /// If a part of the messages is verified, the gateway should tell the verifier to verify only the unverified messages
    #[test]
    fn verify_partially_verified() {
        let msg_store = HashMap::new();
        let msgs = generate_messages(10);
        // half of the messages are verified
        let is_verified = msgs[..5]
            .iter()
            .map(|msg| (msg.cc_id.clone(), true))
            .collect();
        let mut contract = create_contract(msg_store, is_verified);

        // expect: no error, only the unverified messages get verified
        let result = contract.verify_messages(msgs.clone());
        assert!(result.is_ok());
        assert_correct_messages_verified(
            result.unwrap().messages,
            &contract.config.verifier,
            &msgs[5..],
        );
    }

    /// If the verifier query returns an error, the gateway should fail
    #[test]
    fn verify_verifier_fails() {
        let msg_store = HashMap::new();
        let msgs = generate_messages(10);
        let contract = create_contract(msg_store, HashMap::new());

        // make the fake query fail
        let mut contract = Contract {
            query_verifier: |_| bail!(ContractError::QueryVerifier),
            config: contract.config,
            store_msg: contract.store_msg,
        };

        let result = contract.verify_messages(msgs.clone());
        assert!(
            result.is_err_and(|err| matches!(err.current_context(), ContractError::QueryVerifier))
        );
    }

    fn create_contract(
        mut msg_store: HashMap<CrossChainId, NewMessage>,
        is_verified: HashMap<CrossChainId, bool>,
    ) -> Contract<
        impl FnMut(
                aggregate_verifier::msg::QueryMsg,
            ) -> Result<Vec<(CrossChainId, bool)>, ContractError>
            + 'static,
        impl FnMut(CrossChainId, &NewMessage) -> Result<(), ContractError> + 'static,
    > {
        let config = state::Config {
            verifier: Addr::unchecked("verifier"),
            router: Addr::unchecked("router"),
        };

        let store_msg = move |key, msg: &NewMessage| {
            msg_store.insert(key, msg.clone());
            Ok(())
        };
        let query_verifier = move |msg| match msg {
            aggregate_verifier::msg::QueryMsg::IsVerified { messages } => Ok(messages
                .into_iter()
                .map(|msg: NewMessage| {
                    (
                        msg.cc_id.clone(),
                        // if the msg is not know to the verifier, it is not verified
                        is_verified.get(&msg.cc_id).copied().unwrap_or(false),
                    )
                })
                .collect::<Vec<_>>()),
        };
        Contract {
            config,
            store_msg,
            query_verifier,
        }
    }

    fn generate_messages(count: usize) -> Vec<NewMessage> {
        (0..count)
            .map(|i| NewMessage {
                cc_id: CrossChainId {
                    chain: "mock-chain".parse().unwrap(),
                    id: format!("{}{}{}", "hash", ID_SEPARATOR, i).parse().unwrap(),
                },
                destination_address: "idc".parse().unwrap(),
                destination_chain: "mock-chain-2".parse().unwrap(),
                source_address: "idc".parse().unwrap(),
                payload_hash: vec![i as u8, 0, 0, 0].into(),
            })
            .collect()
    }

    fn assert_correct_messages_verified(
        verified_msgs: Vec<SubMsg>,
        expected_verifier: &Addr,
        expected_msgs: &[NewMessage],
    ) {
        assert_eq!(verified_msgs.len(), 1);
        match verified_msgs[0].clone().msg {
            CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr, msg, ..
            }) => {
                assert_eq!(contract_addr, expected_verifier.to_string());

                let msg: aggregate_verifier::msg::ExecuteMsg =
                    serde_json::from_slice(msg.as_slice()).unwrap();
                match msg {
                    aggregate_verifier::msg::ExecuteMsg::VerifyMessages { messages } => {
                        assert_eq!(messages.as_slice(), expected_msgs)
                    }
                }
            }
            _ => panic!("unexpected message type"),
        }
    }
}
