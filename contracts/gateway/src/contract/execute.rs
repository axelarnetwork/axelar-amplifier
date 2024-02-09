use std::collections::HashMap;

use axelar_wasm_std::utils::TryMapExt;
use axelar_wasm_std::VerificationStatus;
use cosmwasm_std::{Addr, DepsMut, Response};
use error_stack::{Result, ResultExt};
use itertools::Itertools;

use crate::error::ContractError;
use connection_router::state::{CrossChainId, Message};

use crate::events::GatewayEvent;
use crate::router::RouterApi;
use crate::state;
use crate::state::Store;
use crate::verifier::{Verifier, VerifierApi, VerifyQuery};

pub struct Contract<V, S>
where
    V: VerifyQuery,
    S: Store,
{
    pub router: RouterApi,
    pub verifier: Verifier<V>,
    pub store: S,
}

impl<'a> Contract<VerifierApi<'a>, state::GatewayStore<'a>> {
    pub fn new(deps: DepsMut) -> Contract<VerifierApi, state::GatewayStore> {
        let store = state::GatewayStore {
            storage: deps.storage,
        };
        let config = store.load_config();
        Contract {
            router: RouterApi {
                address: config.router,
            },
            store,
            verifier: Verifier {
                address: config.verifier.clone(),
                querier: VerifierApi {
                    querier: deps.querier,
                },
            },
        }
    }
}

impl<V, S> Contract<V, S>
where
    V: VerifyQuery,
    S: Store,
{
    pub fn verify_messages(&self, msgs: Vec<Message>) -> Result<Response, ContractError> {
        let partitioned_msgs = ignore_empty_msgs(msgs)
            .try_map(check_for_duplicates)?
            .try_map(|msgs| self.partition_by_verified(msgs))?;

        match partitioned_msgs {
            None => Ok(Response::new()),
            Some((verified, unverified)) => self.verify_unverified_messages(verified, unverified),
        }
    }

    pub fn route_messages(
        &mut self,
        sender: Addr,
        msgs: Vec<Message>,
    ) -> Result<Response, ContractError> {
        if sender == self.router.address {
            Self::route_outgoing_messages(&mut self.store, msgs)
        } else {
            self.route_incoming_messages(msgs)
        }
    }

    fn route_outgoing_messages(
        store: &mut S,
        msgs: Vec<Message>,
    ) -> Result<Response, ContractError> {
        let msgs = check_for_duplicates(msgs)?;

        for msg in msgs.iter() {
            store.save_outgoing_msg(msg.cc_id.clone(), msg)?;
        }

        Ok(Response::new().add_events(
            msgs.into_iter()
                .map(|msg| GatewayEvent::Routing { msg }.into()),
        ))
    }

    fn route_incoming_messages(&self, msgs: Vec<Message>) -> Result<Response, ContractError> {
        let partitioned_msgs = ignore_empty_msgs(msgs)
            .try_map(check_for_duplicates)?
            .try_map(|msgs| self.partition_by_verified(msgs))?;

        match partitioned_msgs {
            None => Ok(Response::new()),
            Some((verified, unverified)) => self.route_verified_messages(verified, unverified),
        }
    }

    fn verify_unverified_messages(
        &self,
        verified: Vec<Message>,
        unverified: Vec<Message>,
    ) -> Result<Response, ContractError> {
        let response = Response::new()
            .add_events(
                verified
                    .clone()
                    .into_iter()
                    .map(|msg| GatewayEvent::AlreadyVerified { msg }.into()),
            )
            .add_events(
                unverified
                    .clone()
                    .into_iter()
                    .map(|msg| GatewayEvent::Verifying { msg }.into()),
            );

        let execute_msg = ignore_empty_msgs(unverified).try_map(|unverified| {
            self.verifier
                .execute(&aggregate_verifier::msg::ExecuteMsg::VerifyMessages {
                    messages: unverified,
                })
        })?;

        match execute_msg {
            None => Ok(response),
            Some(msg) => Ok(response.add_message(msg)),
        }
    }

    fn route_verified_messages(
        &self,
        verified: Vec<Message>,
        unverified: Vec<Message>,
    ) -> Result<Response, ContractError> {
        let response = Response::new()
            .add_events(
                verified
                    .clone()
                    .into_iter()
                    .map(|msg| GatewayEvent::Routing { msg }.into()),
            )
            .add_events(
                unverified
                    .into_iter()
                    .map(|msg| GatewayEvent::UnfitForRouting { msg }.into()),
            );

        let execute_msg = ignore_empty_msgs(verified).try_map(|verified| {
            self.router
                .execute(&connection_router::msg::ExecuteMsg::RouteMessages(verified))
        })?;

        match execute_msg {
            None => Ok(response),
            Some(msg) => Ok(response.add_message(msg)),
        }
    }

    fn partition_by_verified(
        &self,
        msgs: Vec<Message>,
    ) -> Result<(Vec<Message>, Vec<Message>), ContractError> {
        let query_response: Vec<(CrossChainId, VerificationStatus)> =
            self.verifier
                .query(&aggregate_verifier::msg::QueryMsg::GetMessagesStatus {
                    messages: msgs.clone(),
                })?;

        let statuses = query_response.into_iter().collect::<HashMap<_, _>>();

        Ok(msgs.into_iter().partition(|msg| {
            statuses
                .get(&msg.cc_id)
                .copied()
                .unwrap_or(VerificationStatus::None)
                == VerificationStatus::SucceededOnChain
        }))
    }
}

fn ignore_empty_msgs(msgs: Vec<Message>) -> Option<Vec<Message>> {
    if msgs.is_empty() {
        None
    } else {
        Some(msgs)
    }
}

fn check_for_duplicates(msgs: Vec<Message>) -> Result<Vec<Message>, ContractError> {
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
    Ok(msgs)
}

#[cfg(test)]
mod tests {
    use crate::contract::execute::Contract;
    use crate::error::ContractError;
    use crate::router::RouterApi;
    use crate::state;
    use crate::state::Config;
    use crate::verifier::{MockVerifyQuery, Verifier};
    use axelar_wasm_std::VerificationStatus;
    use connection_router::state::{CrossChainId, Message, ID_SEPARATOR};
    use cosmwasm_std::{Addr, CosmosMsg, Response, SubMsg, WasmMsg};
    use error_stack::bail;
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock};

    #[test]
    fn verify_no_messages_do_nothing() {
        let msg_store = Arc::new(RwLock::new(HashMap::new()));
        let contract = create_contract(msg_store.clone(), HashMap::new(), &default_config());

        let result = contract.verify_messages(vec![]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().messages.len(), 0);
    }

    /// If there are messages with duplicate IDs, the gateway should fail
    #[test]
    fn verify_fail_duplicates() {
        let msg_store = Arc::new(RwLock::new(HashMap::new()));
        let mut msgs = generate_messages(10);
        // no messages are verified
        let verified = HashMap::new();
        let contract = create_contract(msg_store.clone(), verified, &default_config());

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
        let verified = msgs
            .iter()
            .map(|msg| (msg.cc_id.clone(), VerificationStatus::SucceededOnChain))
            .collect();
        let contract = create_contract(msg_store.clone(), verified, &default_config());

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
        let verified = HashMap::new();
        let config = default_config();
        let contract = create_contract(msg_store.clone(), verified, &config);

        // try one and many messages (zero messages are tested in verify_all_verified)
        let inputs = vec![msgs[..1].to_vec(), msgs];

        // expect: no error, all input messages get verified
        for input in inputs {
            let result = contract.verify_messages(input.clone());
            assert!(result.is_ok());
            assert_correct_messages_verified(result.unwrap().messages, &config.verifier, &input);
        }
    }

    /// If a part of the messages is verified, the gateway should tell the verifier to verify only the unverified messages
    #[test]
    fn verify_partially_verified() {
        let msg_store = Arc::new(RwLock::new(HashMap::new()));
        let msgs = generate_messages(10);
        // half of the messages are verified
        let verified = msgs[..5]
            .iter()
            .map(|msg| (msg.cc_id.clone(), VerificationStatus::SucceededOnChain))
            .collect();
        let config = default_config();
        let contract = create_contract(msg_store.clone(), verified, &config);

        // expect: no error, only the unverified messages get verified
        let result = contract.verify_messages(msgs.clone());
        assert!(result.is_ok());
        assert_correct_messages_verified(result.unwrap().messages, &config.verifier, &msgs[5..]);
    }

    /// As long as the state of the verifier contract doesn't change, the verify call should always return the same result
    #[test]
    fn verify_is_idempotent() {
        let msg_store = Arc::new(RwLock::new(HashMap::new()));
        let msgs = generate_messages(10);
        // half of the messages are verified
        let verified = msgs[..5]
            .iter()
            .map(|msg| (msg.cc_id.clone(), VerificationStatus::SucceededOnChain))
            .collect();
        let contract = create_contract(msg_store.clone(), verified, &default_config());

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
        let mut querier = MockVerifyQuery::new();
        querier
            .expect_query::<Vec<(CrossChainId, VerificationStatus)>>()
            .returning(|_, _| bail!(ContractError::QueryVerifier));
        let config = default_config();
        let contract = Contract {
            verifier: Verifier {
                querier,
                address: config.verifier.clone(),
            },
            ..create_contract(msg_store.clone(), HashMap::new(), &config)
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
        let verified = HashMap::new();
        let config = default_config();
        let mut contract = create_contract(msg_store.clone(), verified, &config);

        // senders are "router" and "not a router"
        let senders = vec![config.router.clone(), Addr::unchecked("not a router")];

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
        let verified = msgs
            .iter()
            .map(|msg| (msg.cc_id.clone(), VerificationStatus::SucceededOnChain))
            .collect();
        let config = default_config();
        let mut contract = create_contract(msg_store.clone(), verified, &config);

        // try one and many messages (zero messages are tested in route_none_verified)
        let inputs = vec![msgs[..1].to_vec(), msgs];

        for input in inputs {
            // expect: send to router when sender is not the router
            let result = contract.route_messages(Addr::unchecked("not a router"), input.clone());
            assert_correct_messages_routed(result.unwrap().messages, &config.router, &input);

            // expect: store messages when sender is the router
            let result = contract.route_messages(config.router.clone(), input.clone());
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
        let verified = HashMap::new();
        let config = default_config();
        let mut contract = create_contract(msg_store.clone(), verified, &config);

        // try zero, one, many messages
        let inputs = vec![vec![], msgs[..1].to_vec(), msgs];

        for input in inputs {
            // expect: don't call router when sender is not the router
            let result = contract.route_messages(Addr::unchecked("not a router"), input.clone());
            assert_eq!(result.unwrap().messages.len(), 0);

            // expect: store all messages when sender is the router (no verification check)
            let result = contract.route_messages(config.router.clone(), input.clone());
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
        let verified = msgs[..5]
            .iter()
            .map(|msg| (msg.cc_id.clone(), VerificationStatus::SucceededOnChain))
            .collect();
        let config = default_config();
        let mut contract = create_contract(msg_store.clone(), verified, &config);

        // expect: send verified msgs to router when sender is not the router
        let result = contract.route_messages(Addr::unchecked("not a router"), msgs.clone());
        assert_correct_messages_routed(result.unwrap().messages, &config.router, &msgs[..5]);

        // expect: store all messages when sender is the router (no verification check)
        let result = contract.route_messages(config.router.clone(), msgs.clone());
        assert_eq!(result.unwrap().messages.len(), 0);
        assert_correct_messages_stored(&msg_store, &msgs);
    }

    /// When calling routing multiple times with the same input, the outcome should always be the same
    #[test]
    fn route_is_idempotent() {
        let msg_store = Arc::new(RwLock::new(HashMap::new()));
        let msgs = generate_messages(10);
        // half of the messages are verified
        let verified = msgs[..5]
            .iter()
            .map(|msg| (msg.cc_id.clone(), VerificationStatus::SucceededOnChain))
            .collect();
        let config = default_config();
        let mut contract = create_contract(msg_store.clone(), verified, &config);

        let senders = vec![config.router.clone(), Addr::unchecked("not a router")];

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
        let mut querier = MockVerifyQuery::new();
        querier
            .expect_query::<Vec<(CrossChainId, VerificationStatus)>>()
            .returning(|_, _| bail!(ContractError::QueryVerifier));
        let config = default_config();
        let mut contract = Contract {
            verifier: Verifier {
                querier,
                address: config.verifier.clone(),
            },
            ..create_contract(msg_store.clone(), HashMap::new(), &config)
        };

        let result = contract.route_messages(Addr::unchecked("not a router"), msgs.clone());
        assert!(
            result.is_err_and(|err| matches!(err.current_context(), ContractError::QueryVerifier))
        );

        // expect: store all messages when sender is the router (no verification check)
        let result = contract.route_messages(config.router.clone(), msgs.clone());
        assert_eq!(result.unwrap().messages.len(), 0);
        assert_correct_messages_stored(&msg_store, &msgs);
    }

    /// If there are no messages, the gateway should return an empty response
    #[test]
    fn route_no_messages_empty_response() {
        let msg_store = Arc::new(RwLock::new(HashMap::new()));

        let config = default_config();
        let mut contract = create_contract(msg_store.clone(), HashMap::new(), &config);

        // expect: empty response
        let result = contract
            .route_messages(Addr::unchecked("not a router"), vec![])
            .unwrap();
        assert_eq!(result, Response::new());

        // expect: empty response
        let result = contract
            .route_messages(config.router.clone(), vec![])
            .unwrap();
        assert_eq!(result, Response::new());
    }

    fn default_config() -> Config {
        Config {
            verifier: Addr::unchecked("verifier"),
            router: Addr::unchecked("router"),
        }
    }

    /// This uses a RwLock for the msg_store, so it can also be used in assertions while it is borrowed by the contract
    fn create_contract(
        // the store mock requires a 'static type that can be moved into the closure, so we need to use an Arc<> here
        msg_store: Arc<RwLock<HashMap<CrossChainId, Message>>>,
        verified: HashMap<CrossChainId, VerificationStatus>,
        config: &Config,
    ) -> Contract<MockVerifyQuery, state::MockStore> {
        let mut store = state::MockStore::new();
        store.expect_load_config().return_const(config.clone());
        store
            .expect_save_outgoing_msg()
            .returning(move |key, msg: &Message| {
                let mut msg_store = msg_store.write().unwrap();
                msg_store.insert(key, msg.clone());
                Ok(())
            });

        let mut querier = MockVerifyQuery::new();
        querier.expect_query().returning(move |_, msg| match msg {
            aggregate_verifier::msg::QueryMsg::GetMessagesStatus { messages } => Ok(messages
                .into_iter()
                .map(|msg: Message| {
                    (
                        msg.cc_id.clone(),
                        // if the msg is not know to the verifier, it is not verified
                        verified
                            .get(&msg.cc_id)
                            .copied()
                            .unwrap_or(VerificationStatus::None),
                    )
                })
                .collect::<Vec<_>>()),
        });
        Contract {
            router: RouterApi {
                address: config.router.clone(),
            },
            store,
            verifier: Verifier {
                querier,
                address: config.verifier.clone(),
            },
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
                payload_hash: [i as u8; 32],
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
