use std::collections::HashMap;

use cosmwasm_std::{to_binary, Addr, DepsMut, Response, WasmMsg};
use error_stack::{Result, ResultExt};
use itertools::Itertools;

use crate::contract::query;
use crate::contract::query::Verifier;
use crate::error::ContractError;
use connection_router::state::Message;

use crate::events::GatewayEvent;
use crate::state;
use crate::state::{Config, Store};

pub struct Contract<V, S>
where
    V: Verifier,
    S: Store,
{
    pub config: Config,
    pub verifier: V,
    pub store: S,
}

impl<'a> Contract<query::VerifierApi<'a>, state::GatewayStore<'a>> {
    pub fn new(deps: DepsMut) -> Contract<query::VerifierApi, state::GatewayStore> {
        let store = state::GatewayStore {
            storage: deps.storage,
        };
        let config = store.load_config();
        let verifier_addr = config.verifier.clone();
        Contract {
            config,
            store,
            verifier: query::VerifierApi {
                address: verifier_addr,
                querier: deps.querier,
            },
        }
    }
}

impl<V, S> Contract<V, S>
where
    V: Verifier,
    S: Store,
{
    pub fn verify_messages(&self, msgs: Vec<Message>) -> Result<Response, ContractError> {
        // short circuit if there are no messages there is no need to interact with the verifier so it saves gas
        if msgs.is_empty() {
            return Ok(Response::new());
        }

        ensure_unique_ids(&msgs)?;

        let (_, unverified) = self.partition_by_verified(msgs)?;

        // short circuit if there are no unverified messages
        // there is no need to interact with the verifier so it saves gas
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
        msgs: Vec<Message>,
    ) -> Result<Response, ContractError> {
        if sender == self.config.router {
            self.route_outgoing_messages(msgs)
        } else {
            self.route_incoming_messages(msgs)
        }
    }

    fn route_outgoing_messages(&mut self, msgs: Vec<Message>) -> Result<Response, ContractError> {
        ensure_unique_ids(&msgs)?;

        for msg in msgs.iter() {
            self.store.save_outgoing_msg(msg.cc_id.clone(), msg)?;
        }

        Ok(Response::new().add_events(
            msgs.into_iter()
                .map(|msg| GatewayEvent::MessageRouted { msg }.into()),
        ))
    }

    fn route_incoming_messages(&self, msgs: Vec<Message>) -> Result<Response, ContractError> {
        ensure_unique_ids(&msgs)?;

        let (verified, unverified) = self.partition_by_verified(msgs)?;

        let any_verified = !verified.is_empty();

        let mut response = Response::new()
            .add_events(
                verified
                    .clone()
                    .into_iter()
                    .map(|msg| GatewayEvent::MessageRouted { msg }.into()),
            )
            .add_events(
                unverified
                    .into_iter()
                    .map(|msg| GatewayEvent::MessageRoutingFailed { msg }.into()),
            );

        if any_verified {
            response = response.add_message(WasmMsg::Execute {
                contract_addr: self.config.router.to_string(),
                msg: to_binary(&connection_router::msg::ExecuteMsg::RouteMessages(verified))
                    .change_context(ContractError::CreateRouterExecuteMsg)?,
                funds: vec![],
            })
        }

        Ok(response)
    }

    fn partition_by_verified(
        &self,
        msgs: Vec<Message>,
    ) -> Result<(Vec<Message>, Vec<Message>), ContractError> {
        let query_response =
            self.verifier
                .verify(aggregate_verifier::msg::QueryMsg::IsVerified {
                    messages: msgs.to_vec(),
                })?;

        let is_verified = query_response.into_iter().collect::<HashMap<_, _>>();

        Ok(msgs
            .into_iter()
            .partition(|msg| -> bool { is_verified.get(&msg.cc_id).copied().unwrap_or(false) }))
    }
}

fn ensure_unique_ids(msgs: &[Message]) -> Result<(), ContractError> {
    let duplicates: Vec<_> = msgs
        .iter()
        // the following two map instructions are separated on purpose
        // so the duplicate check is done on the typed id instead of just a string
        .map(|m| &m.cc_id)
        .duplicates()
        .map(|cc_id| cc_id.to_string())
        .collect();
    if !duplicates.is_empty() {
        return Err(ContractError::DuplicateMessageIds)
            .attach_printable(duplicates.iter().join(", "));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::contract::execute::Contract;
    use crate::contract::query;
    use crate::error::ContractError;
    use crate::state;
    use connection_router::state::{CrossChainId, Message, ID_SEPARATOR};
    use cosmwasm_std::{Addr, CosmosMsg, SubMsg, WasmMsg};
    use error_stack::bail;
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock};

    /// If there are messages with duplicate IDs, the gateway should fail
    #[test]
    fn verify_fail_duplicates() {
        let msg_store = Arc::new(RwLock::new(HashMap::new()));
        let mut msgs = generate_messages(10);
        // no messages are verified
        let is_verified = HashMap::new();
        let contract = create_contract(msg_store.clone(), is_verified);

        // duplicate some IDs
        msgs[5..]
            .iter_mut()
            .for_each(|msg| msg.cc_id.id = "same_id:000".parse().unwrap());

        let result = contract.verify_messages(msgs);
        assert!(result
            .is_err_and(|err| matches!(err.current_context(), ContractError::DuplicateMessageIds)));
    }

    /// If all messages are verified, the gateway should not call the verifier
    #[test]
    fn verify_all_verified() {
        let msg_store = Arc::new(RwLock::new(HashMap::new()));
        let msgs = generate_messages(10);
        // mark all generated messages as verified
        let is_verified = msgs.iter().map(|msg| (msg.cc_id.clone(), true)).collect();
        let contract = create_contract(msg_store.clone(), is_verified);

        // try zero, one, many messages
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
        let msg_store = Arc::new(RwLock::new(HashMap::new()));
        let msgs = generate_messages(10);
        // no messages are verified
        let is_verified = HashMap::new();
        let contract = create_contract(msg_store.clone(), is_verified);

        // try one and many messages (zero messages are tested in verify_all_verified)
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
        let msg_store = Arc::new(RwLock::new(HashMap::new()));
        let msgs = generate_messages(10);
        // half of the messages are verified
        let is_verified = msgs[..5]
            .iter()
            .map(|msg| (msg.cc_id.clone(), true))
            .collect();
        let contract = create_contract(msg_store.clone(), is_verified);

        // expect: no error, only the unverified messages get verified
        let result = contract.verify_messages(msgs.clone());
        assert!(result.is_ok());
        assert_correct_messages_verified(
            result.unwrap().messages,
            &contract.config.verifier,
            &msgs[5..],
        );
    }

    /// As long as the state of the verifier contract doesn't change, the verify call should always return the same result
    #[test]
    fn verify_is_idempotent() {
        let msg_store = Arc::new(RwLock::new(HashMap::new()));
        let msgs = generate_messages(10);
        // half of the messages are verified
        let is_verified = msgs[..5]
            .iter()
            .map(|msg| (msg.cc_id.clone(), true))
            .collect();
        let contract = create_contract(msg_store.clone(), is_verified);

        // expect: same response when called multiple times and no messages are stored
        let result1 = contract.verify_messages(msgs.clone());
        let result2 = contract.verify_messages(msgs.clone());
        assert_eq!(result1.unwrap(), result2.unwrap());
        assert!(msg_store.read().unwrap().is_empty())
    }

    /// If the verifier query returns an error, the gateway should fail
    #[test]
    fn verify_verifier_fails() {
        let msg_store = Arc::new(RwLock::new(HashMap::new()));
        let msgs = generate_messages(10);

        // make the fake query fail
        let mut verifier = query::MockVerifier::new();
        verifier
            .expect_verify()
            .returning(|_| bail!(ContractError::QueryVerifier));
        let contract = Contract {
            verifier,
            ..create_contract(msg_store.clone(), HashMap::new())
        };

        let result = contract.verify_messages(msgs.clone());
        assert!(
            result.is_err_and(|err| matches!(err.current_context(), ContractError::QueryVerifier))
        );
    }

    /// If there are messages with duplicate IDs, the gateway should fail
    #[test]
    fn route_messages_fail_duplicates() {
        let msg_store = Arc::new(RwLock::new(HashMap::new()));
        let mut msgs = generate_messages(10);
        // no messages are verified
        let is_verified = HashMap::new();
        let mut contract = create_contract(msg_store.clone(), is_verified);

        // senders are "router" and "not a router"
        let senders = vec![
            contract.config.router.clone(),
            Addr::unchecked("not a router"),
        ];

        // duplicate some IDs
        msgs[5..]
            .iter_mut()
            .for_each(|msg| msg.cc_id.id = "same_id:000".parse().unwrap());

        for sender in senders {
            let result = contract.route_messages(sender, msgs.clone());
            assert!(result.is_err_and(|err| matches!(
                err.current_context(),
                ContractError::DuplicateMessageIds
            )));
        }
    }

    /// If all messages are verified, the gateway should
    /// 1. call the router if the sender is not a router
    /// 2. store the msgs to be picked up by relayers if the sender is a router
    #[test]
    fn route_all_verified() {
        let msg_store = Arc::new(RwLock::new(HashMap::new()));

        let msgs = generate_messages(10);
        // mark all generated messages as verified
        let is_verified = msgs.iter().map(|msg| (msg.cc_id.clone(), true)).collect();
        let mut contract = create_contract(msg_store.clone(), is_verified);

        // try one and many messages (zero messages are tested in route_none_verified)
        let inputs = vec![msgs[..1].to_vec(), msgs];

        for input in inputs {
            // expect: send to router when sender is not the router
            let result = contract.route_messages(Addr::unchecked("not a router"), input.clone());
            assert_correct_messages_routed(
                result.unwrap().messages,
                &contract.config.router,
                &input,
            );

            // expect: store messages when sender is the router
            let result = contract.route_messages(contract.config.router.clone(), input.clone());
            assert_eq!(result.unwrap().messages.len(), 0);
            assert_correct_messages_stored(&msg_store, &input);
        }
    }

    /// If none of the messages are verified, the gateway should
    /// 1. not call the router at all if the sender is not a router
    /// 2. store all msgs to be picked up by relayers if the sender is a router, because the gateway trusts the router
    #[test]
    fn route_none_verified() {
        let msg_store = Arc::new(RwLock::new(HashMap::new()));
        let msgs = generate_messages(10);
        // no messages are verified
        let is_verified = HashMap::new();
        let mut contract = create_contract(msg_store.clone(), is_verified);

        // try zero, one, many messages
        let inputs = vec![vec![], msgs[..1].to_vec(), msgs];

        for input in inputs {
            // expect: don't call router when sender is not the router
            let result = contract.route_messages(Addr::unchecked("not a router"), input.clone());
            assert_eq!(result.unwrap().messages.len(), 0);

            // expect: store all messages when sender is the router (no verification check)
            let result = contract.route_messages(contract.config.router.clone(), input.clone());
            assert_eq!(result.unwrap().messages.len(), 0);
            assert_correct_messages_stored(&msg_store, &input);
        }
    }

    /// If a part of the messages is verified, the gateway should
    /// 1. only route verified messages to the router when the sender is not a router
    /// 2. store all msgs to be picked up by relayers if the sender is a router
    #[test]
    fn route_partially_verified() {
        let msg_store = Arc::new(RwLock::new(HashMap::new()));
        let msgs = generate_messages(10);
        // half of the messages are verified
        let is_verified = msgs[..5]
            .iter()
            .map(|msg| (msg.cc_id.clone(), true))
            .collect();
        let mut contract = create_contract(msg_store.clone(), is_verified);

        // expect: send verified msgs to router when sender is not the router
        let result = contract.route_messages(Addr::unchecked("not a router"), msgs.clone());
        assert_correct_messages_routed(
            result.unwrap().messages,
            &contract.config.router,
            &msgs[..5],
        );

        // expect: store all messages when sender is the router (no verification check)
        let result = contract.route_messages(contract.config.router.clone(), msgs.clone());
        assert_eq!(result.unwrap().messages.len(), 0);
        assert_correct_messages_stored(&msg_store, &msgs);
    }

    /// When calling routing multiple times with the same input, the outcome should always be the same
    #[test]
    fn route_is_idempotent() {
        let msg_store = Arc::new(RwLock::new(HashMap::new()));
        let msgs = generate_messages(10);
        // half of the messages are verified
        let is_verified = msgs[..5]
            .iter()
            .map(|msg| (msg.cc_id.clone(), true))
            .collect();
        let mut contract = create_contract(msg_store.clone(), is_verified);

        let senders = vec![
            contract.config.router.clone(),
            Addr::unchecked("not a router"),
        ];

        for sender in senders {
            // expect: response and store state are the same for multiple calls
            let result1 = contract.route_messages(sender.clone(), msgs.clone());
            let msg_store1 = msg_store.read().unwrap().clone();
            let result2 = contract.route_messages(sender, msgs.clone());
            let msg_store2 = msg_store.read().unwrap().clone();
            assert_eq!(result1.unwrap(), result2.unwrap());
            assert_eq!(msg_store1, msg_store2);
        }
    }

    /// If the verifier query returns an error, the gateway should
    /// 1. fail when the sender is not a router
    /// 2. store all messages when the sender is a router (there is no verification check)
    #[test]
    fn route_verifier_fails() {
        let msg_store = Arc::new(RwLock::new(HashMap::new()));
        let msgs = generate_messages(10);

        // make the fake query fail
        let mut verifier = query::MockVerifier::new();
        verifier
            .expect_verify()
            .returning(|_| bail!(ContractError::QueryVerifier));
        let mut contract = Contract {
            verifier,
            ..create_contract(msg_store.clone(), HashMap::new())
        };

        let result = contract.route_messages(Addr::unchecked("not a router"), msgs.clone());
        assert!(
            result.is_err_and(|err| matches!(err.current_context(), ContractError::QueryVerifier))
        );

        // expect: store all messages when sender is the router (no verification check)
        let result = contract.route_messages(contract.config.router.clone(), msgs.clone());
        assert_eq!(result.unwrap().messages.len(), 0);
        assert_correct_messages_stored(&msg_store, &msgs);
    }

    /// This uses a RwLock for the msg_store so it can also be used in assertions while it is borrowed by the contract
    fn create_contract(
        // the store mock requires a 'static type that can be moved into the closure, so we need to use an Arc<> here
        msg_store: Arc<RwLock<HashMap<CrossChainId, Message>>>,
        is_verified: HashMap<CrossChainId, bool>,
    ) -> Contract<query::MockVerifier, state::MockStore> {
        let config = state::Config {
            verifier: Addr::unchecked("verifier"),
            router: Addr::unchecked("router"),
        };

        let mut store = state::MockStore::new();
        store.expect_load_config().return_const(config.clone());
        store
            .expect_save_outgoing_msg()
            .returning(move |key, msg: &Message| {
                let mut msg_store = msg_store.write().unwrap();
                msg_store.insert(key, msg.clone());
                Ok(())
            });

        let mut verifier = query::MockVerifier::new();
        verifier.expect_verify().returning(move |msg| match msg {
            aggregate_verifier::msg::QueryMsg::IsVerified { messages } => Ok(messages
                .into_iter()
                .map(|msg: Message| {
                    (
                        msg.cc_id.clone(),
                        // if the msg is not know to the verifier, it is not verified
                        is_verified.get(&msg.cc_id).copied().unwrap_or(false),
                    )
                })
                .collect::<Vec<_>>()),
        });
        Contract {
            config,
            store,
            verifier,
        }
    }

    fn generate_messages(count: usize) -> Vec<Message> {
        (0..count)
            .map(|i| Message {
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
        expected_msgs: &[Message],
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

    fn assert_correct_messages_routed(
        routed_msgs: Vec<SubMsg>,
        expected_router: &Addr,
        expected_msgs: &[Message],
    ) {
        assert_eq!(routed_msgs.len(), 1);
        match routed_msgs[0].clone().msg {
            CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr, msg, ..
            }) => {
                assert_eq!(contract_addr, expected_router.to_string());

                let msg: connection_router::msg::ExecuteMsg =
                    serde_json::from_slice(msg.as_slice()).unwrap();
                match msg {
                    connection_router::msg::ExecuteMsg::RouteMessages(messages) => {
                        assert_eq!(messages.as_slice(), expected_msgs)
                    }
                    _ => panic!("unexpected message type"),
                }
            }
            _ => panic!("unexpected message type"),
        }
    }

    fn assert_correct_messages_stored(
        locked_msg_store: &RwLock<HashMap<CrossChainId, Message>>,
        expected_msgs: &[Message],
    ) {
        let msg_store = locked_msg_store.read().unwrap();
        assert_eq!((*msg_store).len(), expected_msgs.len());

        assert!(expected_msgs
            .into_iter()
            .all(|msg| { msg_store.get(&msg.cc_id).unwrap() == msg }))
    }
}
