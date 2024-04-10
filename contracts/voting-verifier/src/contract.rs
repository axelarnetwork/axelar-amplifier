#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Attribute, Binary, Deps, DepsMut, Env, Event, MessageInfo, Response, StdResult,
};

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{Config, CONFIG};
use crate::{execute, query};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let config = Config {
        governance: deps.api.addr_validate(&msg.governance_address)?,
        service_name: msg.service_name,
        service_registry_contract: deps.api.addr_validate(&msg.service_registry_address)?,
        source_gateway_address: msg.source_gateway_address,
        voting_threshold: msg.voting_threshold,
        block_expiry: msg.block_expiry,
        confirmation_height: msg.confirmation_height,
        source_chain: msg.source_chain,
        rewards_contract: deps.api.addr_validate(&msg.rewards_address)?,
    };
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new()
        .add_event(Event::new("instantiated").add_attributes(<Vec<Attribute>>::from(config))))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    match msg {
        ExecuteMsg::VerifyMessages { messages } => execute::verify_messages(deps, env, messages),
        ExecuteMsg::Vote { poll_id, votes } => execute::vote(deps, env, info, poll_id, votes),
        ExecuteMsg::EndPoll { poll_id } => execute::end_poll(deps, env, poll_id),
        ExecuteMsg::VerifyWorkerSet {
            message_id,
            new_operators,
        } => execute::verify_worker_set(deps, env, message_id, new_operators),
        ExecuteMsg::UpdateVotingThreshold {
            new_voting_threshold,
        } => {
            execute::require_governance(&deps, info.sender)?;
            execute::update_voting_threshold(deps, new_voting_threshold)
        }
    }
    .map_err(axelar_wasm_std::ContractError::from)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetPoll { poll_id: _ } => {
            todo!()
        }

        QueryMsg::GetMessagesStatus { messages } => {
            to_json_binary(&query::messages_status(deps, &messages)?)
        }
        QueryMsg::GetWorkerSetStatus { new_operators } => {
            to_json_binary(&query::worker_set_status(deps, &new_operators)?)
        }
        QueryMsg::GetCurrentThreshold => to_json_binary(&query::voting_threshold(deps)?),
    }
}

#[cfg(test)]
mod test {

    use cosmwasm_std::{
        from_json,
        testing::{mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage},
        Addr, Empty, Fraction, OwnedDeps, Uint128, Uint64, WasmQuery,
    };

    use axelar_wasm_std::{
        nonempty, operators::Operators, voting::Vote, MajorityThreshold, Threshold,
        VerificationStatus,
    };
    use connection_router_api::{ChainName, CrossChainId, Message};
    use service_registry::state::{
        AuthorizationState, BondingState, WeightedWorker, Worker, WORKER_WEIGHT,
    };

    use crate::{
        error::ContractError,
        events::{TxEventConfirmation, TX_HASH_EVENT_INDEX_SEPARATOR},
        msg::VerifyMessagesResponse,
    };

    use super::*;

    const SENDER: &str = "sender";
    const SERVICE_REGISTRY_ADDRESS: &str = "service_registry_address";
    const REWARDS_ADDRESS: &str = "rewards_address";
    const SERVICE_NAME: &str = "service_name";
    const POLL_BLOCK_EXPIRY: u64 = 100;
    const GOVERNANCE: &str = "governance";

    fn source_chain() -> ChainName {
        "source-chain".parse().unwrap()
    }

    fn governance() -> Addr {
        Addr::unchecked(GOVERNANCE)
    }

    fn initial_voting_threshold() -> MajorityThreshold {
        Threshold::try_from((2, 3)).unwrap().try_into().unwrap()
    }

    fn assert_contract_err_strings_equal(
        actual: impl Into<axelar_wasm_std::ContractError>,
        expected: impl Into<axelar_wasm_std::ContractError>,
    ) {
        assert_eq!(actual.into().to_string(), expected.into().to_string());
    }

    fn workers(num_workers: usize) -> Vec<Worker> {
        let mut workers = vec![];
        for i in 0..num_workers {
            workers.push(Worker {
                address: Addr::unchecked(format!("addr{}", i)),
                bonding_state: BondingState::Bonded {
                    amount: Uint128::from(100u128),
                },
                authorization_state: AuthorizationState::Authorized,
                service_name: SERVICE_NAME.parse().unwrap(),
            })
        }
        workers
    }

    fn setup(workers: Vec<Worker>) -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = mock_dependencies();

        let config = Config {
            governance: governance(),
            service_name: SERVICE_NAME.parse().unwrap(),
            service_registry_contract: Addr::unchecked(SERVICE_REGISTRY_ADDRESS),
            source_gateway_address: "source_gateway_address".parse().unwrap(),
            voting_threshold: initial_voting_threshold(),
            block_expiry: POLL_BLOCK_EXPIRY,
            confirmation_height: 100,
            source_chain: source_chain(),
            rewards_contract: Addr::unchecked(REWARDS_ADDRESS),
        };
        CONFIG.save(deps.as_mut().storage, &config).unwrap();

        deps.querier.update_wasm(move |wq| match wq {
            WasmQuery::Smart { contract_addr, .. } if contract_addr == SERVICE_REGISTRY_ADDRESS => {
                Ok(to_json_binary(
                    &workers
                        .clone()
                        .into_iter()
                        .map(|w| WeightedWorker {
                            worker_info: w,
                            weight: WORKER_WEIGHT,
                        })
                        .collect::<Vec<WeightedWorker>>(),
                )
                .into())
                .into()
            }
            _ => panic!("no mock for this query"),
        });

        deps
    }

    fn message_id(id: &str, index: u64) -> nonempty::String {
        format!("{}{}{}", id, TX_HASH_EVENT_INDEX_SEPARATOR, index)
            .try_into()
            .unwrap()
    }

    fn messages(len: u64) -> Vec<Message> {
        (0..len)
            .map(|i| Message {
                cc_id: CrossChainId {
                    chain: source_chain(),
                    id: message_id("id", i),
                },
                source_address: format!("source_address{i}").parse().unwrap(),
                destination_chain: format!("destination-chain{i}").parse().unwrap(),
                destination_address: format!("destination_address{i}").parse().unwrap(),
                payload_hash: [0; 32],
            })
            .collect()
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn mock_env_expired() -> Env {
        let mut env = mock_env();
        env.block.height += POLL_BLOCK_EXPIRY;
        env
    }

    #[test]
    fn should_fail_if_messages_are_not_from_same_source() {
        let workers = workers(2);
        let mut deps = setup(workers.clone());

        let msg = ExecuteMsg::VerifyMessages {
            messages: vec![
                Message {
                    cc_id: CrossChainId {
                        chain: source_chain(),
                        id: message_id("id", 1),
                    },
                    source_address: "source_address1".parse().unwrap(),
                    destination_chain: "destination-chain1".parse().unwrap(),
                    destination_address: "destination_address1".parse().unwrap(),
                    payload_hash: [0; 32],
                },
                Message {
                    cc_id: CrossChainId {
                        chain: "other-chain".parse().unwrap(),
                        id: message_id("id", 2),
                    },
                    source_address: "source_address2".parse().unwrap(),
                    destination_chain: "destination-chain2".parse().unwrap(),
                    destination_address: "destination_address2".parse().unwrap(),
                    payload_hash: [0; 32],
                },
            ],
        };
        let err = execute(deps.as_mut(), mock_env(), mock_info(SENDER, &[]), msg).unwrap_err();
        assert_contract_err_strings_equal(err, ContractError::SourceChainMismatch(source_chain()));
    }

    #[test]
    fn should_verify_messages_if_not_verified() {
        let workers = workers(2);
        let mut deps = setup(workers.clone());

        let msg = ExecuteMsg::VerifyMessages {
            messages: messages(2),
        };

        let res = execute(deps.as_mut(), mock_env(), mock_info(SENDER, &[]), msg).unwrap();
        let reply: VerifyMessagesResponse = from_json(res.data.unwrap()).unwrap();
        assert_eq!(reply.verification_statuses.len(), 2);
        assert_eq!(
            reply.verification_statuses,
            vec![
                (
                    CrossChainId {
                        id: message_id("id", 0),
                        chain: source_chain()
                    },
                    VerificationStatus::None
                ),
                (
                    CrossChainId {
                        id: message_id("id", 1),
                        chain: source_chain()
                    },
                    VerificationStatus::None
                ),
            ]
        );
    }

    #[test]
    fn should_not_verify_messages_if_in_progress() {
        let workers = workers(2);
        let mut deps = setup(workers.clone());
        let messages_in_progress = 3;
        let new_messages = 2;

        execute(
            deps.as_mut(),
            mock_env(),
            mock_info(SENDER, &[]),
            ExecuteMsg::VerifyMessages {
                messages: messages(messages_in_progress),
            },
        )
        .unwrap();

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(SENDER, &[]),
            ExecuteMsg::VerifyMessages {
                messages: messages(messages_in_progress + new_messages), // creates the same messages + some new ones
            },
        )
        .unwrap();

        let messages: Vec<TxEventConfirmation> = serde_json::from_str(
            &res.events
                .into_iter()
                .find(|event| event.ty == "messages_poll_started")
                .unwrap()
                .attributes
                .into_iter()
                .find_map(|attribute| {
                    if attribute.key == "messages" {
                        Some(attribute.value)
                    } else {
                        None
                    }
                })
                .unwrap(),
        )
        .unwrap();

        assert_eq!(messages.len() as u64, new_messages);
    }

    #[test]
    fn should_retry_if_message_not_verified() {
        let workers = workers(2);
        let mut deps = setup(workers.clone());

        let msg = ExecuteMsg::VerifyMessages {
            messages: messages(1),
        };
        execute(
            deps.as_mut(),
            mock_env(),
            mock_info(SENDER, &[]),
            msg.clone(),
        )
        .unwrap();

        execute(
            deps.as_mut(),
            mock_env_expired(),
            mock_info(SENDER, &[]),
            ExecuteMsg::EndPoll {
                poll_id: Uint64::one().into(),
            },
        )
        .unwrap();

        // retries same message
        let res = execute(deps.as_mut(), mock_env(), mock_info(SENDER, &[]), msg).unwrap();

        let messages: Vec<TxEventConfirmation> = serde_json::from_str(
            &res.events
                .into_iter()
                .find(|event| event.ty == "messages_poll_started")
                .unwrap()
                .attributes
                .into_iter()
                .find_map(|attribute| {
                    if attribute.key == "messages" {
                        Some(attribute.value)
                    } else {
                        None
                    }
                })
                .unwrap(),
        )
        .unwrap();

        assert_eq!(messages.len() as u64, 1);
    }

    #[test]
    fn should_retry_if_status_not_final() {
        let workers = workers(2);
        let mut deps = setup(workers.clone());

        let messages = messages(4);

        // 1. First verification

        let msg_verify = ExecuteMsg::VerifyMessages {
            messages: messages.clone(),
        };

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(SENDER, &[]),
            msg_verify.clone(),
        );
        assert!(res.is_ok());

        // 2. Workers cast votes, but only reach consensus on the first three messages

        workers.iter().enumerate().for_each(|(i, worker)| {
            let msg = ExecuteMsg::Vote {
                poll_id: 1u64.into(),
                votes: vec![
                    Vote::SucceededOnChain,
                    Vote::FailedOnChain,
                    Vote::NotFound,
                    if i % 2 == 0 {
                        // workers vote is divided so no consensus is reached
                        Vote::SucceededOnChain
                    } else {
                        Vote::FailedOnChain
                    },
                ],
            };

            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(worker.address.as_str(), &[]),
                msg,
            );
            assert!(res.is_ok());
        });

        // 3. Poll is ended. First three messages reach consensus, last one does not

        let msg = ExecuteMsg::EndPoll {
            poll_id: 1u64.into(),
        };

        let res = execute(
            deps.as_mut(),
            mock_env_expired(),
            mock_info(SENDER, &[]),
            msg,
        );
        assert!(res.is_ok());

        let res: Vec<(CrossChainId, VerificationStatus)> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetMessagesStatus {
                    messages: messages.clone(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            res,
            vec![
                (
                    messages[0].cc_id.clone(),
                    VerificationStatus::SucceededOnChain
                ),
                (messages[1].cc_id.clone(), VerificationStatus::FailedOnChain),
                (messages[2].cc_id.clone(), VerificationStatus::NotFound),
                (
                    messages[3].cc_id.clone(),
                    VerificationStatus::FailedToVerify
                )
            ]
        );

        // 3. Retry verification. From the three messages that reached consensus, only the first two have a
        // status considered final (SucceededOnChan or FailedOnChain), so the last two are retried

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(SENDER, &[]),
            msg_verify,
        );
        assert!(res.is_ok());

        let res: Vec<(CrossChainId, VerificationStatus)> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetMessagesStatus {
                    messages: messages.clone(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            res,
            vec![
                (
                    messages[0].cc_id.clone(),
                    VerificationStatus::SucceededOnChain
                ),
                (messages[1].cc_id.clone(), VerificationStatus::FailedOnChain),
                (messages[2].cc_id.clone(), VerificationStatus::InProgress),
                (messages[3].cc_id.clone(), VerificationStatus::InProgress)
            ]
        );
    }

    #[test]
    fn should_query_message_statuses() {
        let workers = workers(2);
        let mut deps = setup(workers.clone());

        let messages = messages(10);
        let msg = ExecuteMsg::VerifyMessages {
            messages: messages.clone(),
        };

        let res = execute(deps.as_mut(), mock_env(), mock_info(SENDER, &[]), msg).unwrap();

        let reply: VerifyMessagesResponse = from_json(res.data.unwrap()).unwrap();

        assert_eq!(reply.verification_statuses.len(), messages.len());
        assert_eq!(
            reply.verification_statuses,
            messages
                .iter()
                .map(|message| (message.cc_id.clone(), VerificationStatus::None))
                .collect::<Vec<(_, _)>>()
        );

        let statuses: Vec<(CrossChainId, VerificationStatus)> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetMessagesStatus {
                    messages: messages.clone(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            statuses,
            messages
                .iter()
                .map(|message| (message.cc_id.clone(), VerificationStatus::InProgress))
                .collect::<Vec<(_, _)>>()
        );

        let msg = ExecuteMsg::Vote {
            poll_id: Uint64::one().into(),
            votes: (0..messages.len())
                .map(|i| {
                    if i % 2 == 0 {
                        Vote::SucceededOnChain
                    } else {
                        Vote::NotFound
                    }
                })
                .collect::<Vec<_>>(),
        };

        workers.iter().for_each(|worker| {
            execute(
                deps.as_mut(),
                mock_env(),
                mock_info(worker.address.as_str(), &[]),
                msg.clone(),
            )
            .unwrap();
        });

        let msg = ExecuteMsg::EndPoll {
            poll_id: Uint64::one().into(),
        };

        execute(
            deps.as_mut(),
            mock_env_expired(),
            mock_info(SENDER, &[]),
            msg,
        )
        .unwrap();

        let statuses: Vec<(CrossChainId, VerificationStatus)> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetMessagesStatus {
                    messages: messages.clone(),
                },
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            statuses,
            messages
                .iter()
                .enumerate()
                .map(|(i, message)| (
                    message.cc_id.clone(),
                    if i % 2 == 0 {
                        VerificationStatus::SucceededOnChain
                    } else {
                        VerificationStatus::NotFound
                    }
                ))
                .collect::<Vec<(_, _)>>()
        );
    }

    #[test]
    fn should_start_worker_set_confirmation() {
        let workers = workers(2);
        let mut deps = setup(workers.clone());

        let operators = Operators::new(vec![(vec![0, 1, 0, 1].into(), 1u64.into())], 1u64.into());
        let msg = ExecuteMsg::VerifyWorkerSet {
            message_id: message_id("id", 0),
            new_operators: operators.clone(),
        };
        let res = execute(deps.as_mut(), mock_env(), mock_info(SENDER, &[]), msg);
        assert!(res.is_ok());

        let res: VerificationStatus = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetWorkerSetStatus {
                    new_operators: operators.clone(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(res, VerificationStatus::InProgress);
    }

    #[test]
    fn should_confirm_worker_set() {
        let workers = workers(2);
        let mut deps = setup(workers.clone());

        let operators = Operators::new(vec![(vec![0, 1, 0, 1].into(), 1u64.into())], 1u64.into());
        let msg = ExecuteMsg::VerifyWorkerSet {
            message_id: message_id("id", 0),
            new_operators: operators.clone(),
        };
        let res = execute(deps.as_mut(), mock_env(), mock_info(SENDER, &[]), msg);
        assert!(res.is_ok());

        let msg = ExecuteMsg::Vote {
            poll_id: 1u64.into(),
            votes: vec![Vote::SucceededOnChain],
        };
        for worker in workers {
            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(worker.address.as_str(), &[]),
                msg.clone(),
            );
            assert!(res.is_ok());
        }

        let res = execute(
            deps.as_mut(),
            mock_env_expired(),
            mock_info(SENDER, &[]),
            ExecuteMsg::EndPoll {
                poll_id: 1u64.into(),
            },
        );
        assert!(res.is_ok());

        let res: VerificationStatus = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetWorkerSetStatus {
                    new_operators: operators.clone(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(res, VerificationStatus::SucceededOnChain);
    }

    #[test]
    fn should_not_confirm_worker_set() {
        let workers = workers(2);
        let mut deps = setup(workers.clone());

        let operators = Operators::new(vec![(vec![0, 1, 0, 1].into(), 1u64.into())], 1u64.into());
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(SENDER, &[]),
            ExecuteMsg::VerifyWorkerSet {
                message_id: message_id("id", 0),
                new_operators: operators.clone(),
            },
        );
        assert!(res.is_ok());

        for worker in workers {
            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(worker.address.as_str(), &[]),
                ExecuteMsg::Vote {
                    poll_id: 1u64.into(),
                    votes: vec![Vote::NotFound],
                },
            );
            assert!(res.is_ok());
        }

        let res = execute(
            deps.as_mut(),
            mock_env_expired(),
            mock_info(SENDER, &[]),
            ExecuteMsg::EndPoll {
                poll_id: 1u64.into(),
            },
        );
        assert!(res.is_ok());

        let res: VerificationStatus = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetWorkerSetStatus {
                    new_operators: operators.clone(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(res, VerificationStatus::NotFound);
    }

    #[test]
    fn should_confirm_worker_set_after_failed() {
        let workers = workers(2);
        let mut deps = setup(workers.clone());

        let operators = Operators::new(vec![(vec![0, 1, 0, 1].into(), 1u64.into())], 1u64.into());
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(SENDER, &[]),
            ExecuteMsg::VerifyWorkerSet {
                message_id: message_id("id", 0),
                new_operators: operators.clone(),
            },
        );
        assert!(res.is_ok());

        for worker in &workers {
            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(worker.address.as_str(), &[]),
                ExecuteMsg::Vote {
                    poll_id: 1u64.into(),
                    votes: vec![Vote::NotFound],
                },
            );
            assert!(res.is_ok());
        }

        let res = execute(
            deps.as_mut(),
            mock_env_expired(),
            mock_info(SENDER, &[]),
            ExecuteMsg::EndPoll {
                poll_id: 1u64.into(),
            },
        );
        assert!(res.is_ok());

        let res: VerificationStatus = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetWorkerSetStatus {
                    new_operators: operators.clone(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(res, VerificationStatus::NotFound);

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(SENDER, &[]),
            ExecuteMsg::VerifyWorkerSet {
                message_id: message_id("id", 0),
                new_operators: operators.clone(),
            },
        );
        assert!(res.is_ok());

        for worker in workers {
            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(worker.address.as_str(), &[]),
                ExecuteMsg::Vote {
                    poll_id: 2u64.into(),
                    votes: vec![Vote::SucceededOnChain],
                },
            );
            assert!(res.is_ok());
        }

        let res = execute(
            deps.as_mut(),
            mock_env_expired(),
            mock_info(SENDER, &[]),
            ExecuteMsg::EndPoll {
                poll_id: 2u64.into(),
            },
        );
        assert!(res.is_ok());

        let res: VerificationStatus = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetWorkerSetStatus {
                    new_operators: operators.clone(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(res, VerificationStatus::SucceededOnChain);
    }

    #[test]
    fn should_not_confirm_twice() {
        let workers = workers(2);
        let mut deps = setup(workers.clone());

        let operators = Operators::new(vec![(vec![0, 1, 0, 1].into(), 1u64.into())], 1u64.into());
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(SENDER, &[]),
            ExecuteMsg::VerifyWorkerSet {
                message_id: message_id("id", 0),
                new_operators: operators.clone(),
            },
        );
        assert!(res.is_ok());
        for worker in workers {
            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(worker.address.as_str(), &[]),
                ExecuteMsg::Vote {
                    poll_id: 1u64.into(),
                    votes: vec![Vote::SucceededOnChain],
                },
            );
            assert!(res.is_ok());
        }

        let res = execute(
            deps.as_mut(),
            mock_env_expired(),
            mock_info(SENDER, &[]),
            ExecuteMsg::EndPoll {
                poll_id: 1u64.into(),
            },
        );
        assert!(res.is_ok());

        // try again, should fail
        let err = execute(
            deps.as_mut(),
            mock_env_expired(),
            mock_info(SENDER, &[]),
            ExecuteMsg::VerifyWorkerSet {
                message_id: message_id("id", 0),
                new_operators: operators.clone(),
            },
        )
        .unwrap_err();
        assert_contract_err_strings_equal(err, ContractError::WorkerSetAlreadyConfirmed);
    }

    #[test]
    fn should_be_able_to_update_threshold_and_then_query_new_threshold() {
        let workers = workers(2);
        let mut deps = setup(workers.clone());

        let new_voting_threshold: MajorityThreshold = Threshold::try_from((
            initial_voting_threshold().numerator().u64() + 1,
            initial_voting_threshold().denominator().u64() + 1,
        ))
        .unwrap()
        .try_into()
        .unwrap();

        execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE, &[]),
            ExecuteMsg::UpdateVotingThreshold {
                new_voting_threshold,
            },
        )
        .unwrap();

        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCurrentThreshold).unwrap();

        let threshold: MajorityThreshold = from_json(res).unwrap();
        assert_eq!(threshold, new_voting_threshold);
    }

    #[test]
    fn threshold_changes_should_not_affect_existing_polls() {
        let workers = workers(10);
        let initial_threshold = initial_voting_threshold();
        let majority = (workers.len() as u64 * initial_threshold.numerator().u64())
            .div_ceil(initial_threshold.denominator().u64());

        let mut deps = setup(workers.clone());

        let messages = messages(1);

        execute(
            deps.as_mut(),
            mock_env(),
            mock_info(SENDER, &[]),
            ExecuteMsg::VerifyMessages {
                messages: messages.clone(),
            },
        )
        .unwrap();

        // simulate a majority of workers voting for succeeded on chain
        workers.iter().enumerate().for_each(|(i, worker)| {
            if i >= majority as usize {
                return;
            }
            let msg = ExecuteMsg::Vote {
                poll_id: 1u64.into(),
                votes: vec![Vote::SucceededOnChain],
            };

            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(worker.address.as_str(), &[]),
                msg,
            );
            assert!(res.is_ok());
        });

        // increase the threshold. Not enough workers voted to meet the new majority,
        // but threshold changes should not affect existing polls
        let new_voting_threshold: MajorityThreshold =
            Threshold::try_from((majority + 1, workers.len() as u64))
                .unwrap()
                .try_into()
                .unwrap();

        execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE, &[]),
            ExecuteMsg::UpdateVotingThreshold {
                new_voting_threshold,
            },
        )
        .unwrap();

        execute(
            deps.as_mut(),
            mock_env_expired(),
            mock_info(SENDER, &[]),
            ExecuteMsg::EndPoll {
                poll_id: 1u64.into(),
            },
        )
        .unwrap();

        let res: Vec<(CrossChainId, VerificationStatus)> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetMessagesStatus {
                    messages: messages.clone(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            res,
            vec![(
                messages[0].cc_id.clone(),
                VerificationStatus::SucceededOnChain
            )]
        );
    }

    #[test]
    fn threshold_changes_should_affect_new_polls() {
        let workers = workers(10);
        let initial_threshold = initial_voting_threshold();
        let old_majority = (workers.len() as u64 * initial_threshold.numerator().u64())
            .div_ceil(initial_threshold.denominator().u64());

        let mut deps = setup(workers.clone());

        // increase the threshold prior to starting a poll
        let new_voting_threshold: MajorityThreshold =
            Threshold::try_from((old_majority + 1, workers.len() as u64))
                .unwrap()
                .try_into()
                .unwrap();

        execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE, &[]),
            ExecuteMsg::UpdateVotingThreshold {
                new_voting_threshold,
            },
        )
        .unwrap();

        let messages = messages(1);

        // start the poll, should just the new threshold
        execute(
            deps.as_mut(),
            mock_env(),
            mock_info(SENDER, &[]),
            ExecuteMsg::VerifyMessages {
                messages: messages.clone(),
            },
        )
        .unwrap();

        // simulate old_majority of workers voting succeeded on chain,
        // which is one less than the updated majority. The messages
        // should not receive enough votes to be considered verified
        workers.iter().enumerate().for_each(|(i, worker)| {
            if i >= old_majority as usize {
                return;
            }
            let msg = ExecuteMsg::Vote {
                poll_id: 1u64.into(),
                votes: vec![Vote::SucceededOnChain],
            };

            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(worker.address.as_str(), &[]),
                msg,
            );
            assert!(res.is_ok());
        });

        execute(
            deps.as_mut(),
            mock_env_expired(),
            mock_info(SENDER, &[]),
            ExecuteMsg::EndPoll {
                poll_id: 1u64.into(),
            },
        )
        .unwrap();

        let res: Vec<(CrossChainId, VerificationStatus)> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetMessagesStatus {
                    messages: messages.clone(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            res,
            vec![(
                messages[0].cc_id.clone(),
                VerificationStatus::FailedToVerify
            )]
        );
    }
}
