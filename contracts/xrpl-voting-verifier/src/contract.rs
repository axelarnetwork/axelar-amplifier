use axelar_wasm_std::{address, permission_control, FnExt};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Attribute, Binary, Deps, DepsMut, Empty, Env, Event, MessageInfo, Response,
};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{Config, CONFIG};

mod execute;
mod query;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let governance = address::validate_cosmwasm_address(deps.api, &msg.governance_address)?;
    permission_control::set_governance(deps.storage, &governance)?;

    let config = Config {
        service_name: msg.service_name,
        service_registry_contract: address::validate_cosmwasm_address(deps.api, &msg.service_registry_address)?,
        source_gateway_address: msg.source_gateway_address.to_string().try_into().map_err(|_| ContractError::InvalidSourceGatewayAddress)?,
        voting_threshold: msg.voting_threshold,
        block_expiry: msg.block_expiry,
        confirmation_height: msg.confirmation_height,
        source_chain: msg.source_chain,
        rewards_contract:address::validate_cosmwasm_address(deps.api, &msg.rewards_address)?,
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
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    match msg.ensure_permissions(deps.storage, &info.sender)? {
        ExecuteMsg::VerifyMessages(messages) => Ok(execute::verify_messages(deps, env, messages)?),
        ExecuteMsg::Vote { poll_id, votes } => Ok(execute::vote(deps, env, info, poll_id, votes)?),
        ExecuteMsg::EndPoll { poll_id } => Ok(execute::end_poll(deps, env, poll_id)?),
        ExecuteMsg::UpdateVotingThreshold {
            new_voting_threshold,
        } => Ok(execute::update_voting_threshold(
            deps,
            new_voting_threshold,
        )?),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps,
    env: Env,
    msg: QueryMsg
) -> Result<Binary, axelar_wasm_std::error::ContractError> {
    match msg {
        QueryMsg::Poll { poll_id } => {
            to_json_binary(&query::poll_response(deps, env.block.height, poll_id)?)
        }
        QueryMsg::MessagesStatus(messages) => {
            to_json_binary(&query::messages_status(deps.storage, &messages, env.block.height)?)
        }
        QueryMsg::CurrentThreshold => to_json_binary(&query::voting_threshold(deps)?),
    }?
    .then(Ok)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    _deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    Ok(Response::default())
}

#[cfg(test)]
mod test {
    use axelar_wasm_std::voting::Vote;
    use axelar_wasm_std::{
        nonempty, MajorityThreshold, Threshold, VerificationStatus
    };
    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{from_json, Addr, Empty, Fraction, HexBinary, OwnedDeps, Uint64, WasmQuery};
    use rand::Rng;
    use router_api::ChainName;
    use service_registry::{
        AuthorizationState, BondingState, Verifier, WeightedVerifier, VERIFIER_WEIGHT,
    };
    use sha3::{Digest, Keccak256};
    use xrpl_types::msg::{XRPLMessage, XRPLUserMessage};
    use xrpl_types::types::{TxHash, XRPLAccountId, XRPLPaymentAmount};

    use crate::msg::MessageStatus;

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

    fn initial_voting_threshold() -> MajorityThreshold {
        Threshold::try_from((2, 3)).unwrap().try_into().unwrap()
    }

    fn verifiers(num_verifiers: usize) -> Vec<Verifier> {
        let mut verifiers = vec![];
        for i in 0..num_verifiers {
            verifiers.push(Verifier {
                address: Addr::unchecked(format!("addr{}", i)),
                bonding_state: BondingState::Bonded {
                    amount: nonempty::Uint128::try_from(100u128).unwrap(),
                },
                authorization_state: AuthorizationState::Authorized,
                service_name: SERVICE_NAME.parse().unwrap(),
            })
        }
        verifiers
    }

    fn setup(verifiers: Vec<Verifier>) -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = mock_dependencies();

        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            InstantiateMsg {
                governance_address: GOVERNANCE.parse().unwrap(),
                service_registry_address: SERVICE_REGISTRY_ADDRESS.parse().unwrap(),
                service_name: SERVICE_NAME.parse().unwrap(),
                source_gateway_address: XRPLAccountId::from([0u8; 20]),
                voting_threshold: initial_voting_threshold(),
                block_expiry: POLL_BLOCK_EXPIRY.try_into().unwrap(),
                confirmation_height: 100,
                source_chain: source_chain(),
                rewards_address: REWARDS_ADDRESS.parse().unwrap(),
            },
        )
        .unwrap();

        deps.querier.update_wasm(move |wq| match wq {
            WasmQuery::Smart { contract_addr, .. } if contract_addr == SERVICE_REGISTRY_ADDRESS => {
                Ok(to_json_binary(
                    &verifiers
                        .clone()
                        .into_iter()
                        .map(|v| WeightedVerifier {
                            verifier_info: v,
                            weight: VERIFIER_WEIGHT,
                        })
                        .collect::<Vec<WeightedVerifier>>(),
                )
                .into())
                .into()
            }
            _ => panic!("no mock for this query"),
        });

        deps
    }

    fn message_id(id: &str) -> TxHash {
        let digest: [u8; 32] = Keccak256::digest(id.as_bytes()).into();
        TxHash::new(digest)
    }

    fn messages(len: u32) -> Vec<XRPLMessage> {
        (0..len)
            .map(|i| XRPLMessage::UserMessage(XRPLUserMessage {
                tx_id: message_id("id"),
                source_address: XRPLAccountId::new(rand::thread_rng().gen()),
                destination_chain: format!("destination-chain{i}").parse().unwrap(),
                destination_address: nonempty::HexBinary::try_from(HexBinary::from_hex("1234").unwrap()).unwrap(),
                payload_hash: None,
                amount: XRPLPaymentAmount::Drops(u64::from(i)*1_000_000),
            }))
            .collect()
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn mock_env_expired() -> Env {
        let mut env = mock_env();
        env.block.height += POLL_BLOCK_EXPIRY;
        env
    }

    fn msgs_statuses(messages: Vec<XRPLMessage>, status: VerificationStatus) -> Vec<MessageStatus> {
        messages
            .iter()
            .map(|message| MessageStatus::new(message.clone(), status))
            .collect()
    }

    #[test]
    fn should_not_verify_messages_if_in_progress() {
        let verifiers = verifiers(2);
        let mut deps = setup(verifiers.clone());
        let messages_count = 5;
        let messages_in_progress = 3;
        let messages = messages(messages_count as u32);

        execute(
            deps.as_mut(),
            mock_env(),
            mock_info(SENDER, &[]),
            ExecuteMsg::VerifyMessages(
                messages[0..messages_in_progress].to_vec(), // verify a subset of the messages
            ),
        )
        .unwrap();

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(SENDER, &[]),
            ExecuteMsg::VerifyMessages(
                messages.clone(), // verify all messages including the ones from previous execution
            ),
        )
        .unwrap();

        let actual: Vec<XRPLMessage> = serde_json::from_str(
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

        // messages starting after the ones already in progress
        let expected = &messages[messages_in_progress..];

        assert_eq!(actual, expected);
    }

    #[test]
    fn should_retry_if_message_not_verified() {
        let verifiers = verifiers(2);
        let mut deps = setup(verifiers.clone());
        let messages = messages(5);

        let msg = ExecuteMsg::VerifyMessages(messages.clone());
        execute(
            deps.as_mut(),
            mock_env(),
            mock_info(SENDER, &[]),
            msg.clone(),
        )
        .unwrap();

        // confirm it was not verified
        let status: Vec<MessageStatus> = from_json(
            query(
                deps.as_ref(),
                mock_env_expired(),
                QueryMsg::MessagesStatus(messages.clone()),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            status,
            msgs_statuses(messages.clone(), VerificationStatus::FailedToVerify)
        );

        // retries same message
        let res = execute(
            deps.as_mut(),
            mock_env_expired(),
            mock_info(SENDER, &[]),
            msg,
        )
        .unwrap();

        let actual: Vec<XRPLMessage> = serde_json::from_str(
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

        let expected = messages;

        assert_eq!(actual, expected);
    }

    #[test]
    fn should_retry_if_status_not_final() {
        let verifiers = verifiers(2);
        let mut deps = setup(verifiers.clone());

        let messages = messages(4);

        // 1. First verification

        let msg_verify = ExecuteMsg::VerifyMessages(messages.clone());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(SENDER, &[]),
            msg_verify.clone(),
        );
        assert!(res.is_ok());

        // 2. Verifiers cast votes, but only reach consensus on the first three messages

        verifiers.iter().enumerate().for_each(|(i, verifier)| {
            let msg = ExecuteMsg::Vote {
                poll_id: 1u64.into(),
                votes: vec![
                    Vote::SucceededOnChain,
                    Vote::FailedOnChain,
                    Vote::NotFound,
                    if i % 2 == 0 {
                        // verifiers vote is divided so no consensus is reached
                        Vote::SucceededOnChain
                    } else {
                        Vote::FailedOnChain
                    },
                ],
            };

            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(verifier.address.as_str(), &[]),
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

        let res: Vec<MessageStatus> = from_json(
            query(
                deps.as_ref(),
                mock_env_expired(),
                QueryMsg::MessagesStatus(messages.clone()),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            res,
            vec![
                MessageStatus::new(
                    messages[0].clone(),
                    VerificationStatus::SucceededOnSourceChain
                ),
                MessageStatus::new(messages[1].clone(), VerificationStatus::FailedOnSourceChain),
                MessageStatus::new(
                    messages[2].clone(),
                    VerificationStatus::NotFoundOnSourceChain
                ),
                MessageStatus::new(messages[3].clone(), VerificationStatus::FailedToVerify)
            ]
        );

        // 3. Retry verification. From the three messages that reached consensus, only the first two have a
        // status considered final (SucceededOnChan or FailedOnChain), so the last two are retried

        let res = execute(
            deps.as_mut(),
            mock_env_expired(),
            mock_info(SENDER, &[]),
            msg_verify,
        );
        assert!(res.is_ok());

        let res: Vec<MessageStatus> = from_json(
            query(
                deps.as_ref(),
                mock_env_expired(),
                QueryMsg::MessagesStatus(messages.clone()),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            res,
            vec![
                MessageStatus::new(
                    messages[0].clone(),
                    VerificationStatus::SucceededOnSourceChain
                ),
                MessageStatus::new(messages[1].clone(), VerificationStatus::FailedOnSourceChain),
                MessageStatus::new(messages[2].clone(), VerificationStatus::InProgress),
                MessageStatus::new(messages[3].clone(), VerificationStatus::InProgress)
            ]
        );
    }

    #[test]
    fn should_query_status_none_when_not_verified() {
        let verifiers = verifiers(2);
        let deps = setup(verifiers.clone());

        let messages = messages(10);

        let statuses: Vec<MessageStatus> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::MessagesStatus(messages.clone()),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            statuses,
            msgs_statuses(messages, VerificationStatus::Unknown)
        );
    }

    #[test]
    fn should_query_status_in_progress_when_no_consensus_and_poll_not_ended() {
        let verifiers = verifiers(2);
        let mut deps = setup(verifiers.clone());

        let messages = messages(10);

        // starts verification process
        execute(
            deps.as_mut(),
            mock_env(),
            mock_info(SENDER, &[]),
            ExecuteMsg::VerifyMessages(messages.clone()),
        )
        .unwrap();

        let statuses: Vec<MessageStatus> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::MessagesStatus(messages.clone()),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            statuses,
            msgs_statuses(messages.clone(), VerificationStatus::InProgress)
        );
    }

    #[test]
    fn should_query_status_failed_to_verify_when_no_consensus_and_poll_expired() {
        let verifiers = verifiers(2);
        let mut deps = setup(verifiers.clone());

        let messages = messages(10);

        // starts verification process
        execute(
            deps.as_mut(),
            mock_env(),
            mock_info(SENDER, &[]),
            ExecuteMsg::VerifyMessages(messages.clone()),
        )
        .unwrap();

        let statuses: Vec<MessageStatus> = from_json(
            query(
                deps.as_ref(),
                mock_env_expired(),
                QueryMsg::MessagesStatus(messages.clone()),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            statuses,
            msgs_statuses(messages.clone(), VerificationStatus::FailedToVerify)
        );
    }

    #[test]
    fn should_query_status_according_to_vote() {
        let test_cases = [
            (
                Vote::SucceededOnChain,
                VerificationStatus::SucceededOnSourceChain,
            ),
            (Vote::FailedOnChain, VerificationStatus::FailedOnSourceChain),
            (Vote::NotFound, VerificationStatus::NotFoundOnSourceChain),
        ]
        .iter()
        .collect::<Vec<_>>();

        for (consensus_vote, expected_status) in test_cases {
            let verifiers = verifiers(2);
            let mut deps = setup(verifiers.clone());

            let messages = messages(10);

            // starts verification process
            execute(
                deps.as_mut(),
                mock_env(),
                mock_info(SENDER, &[]),
                ExecuteMsg::VerifyMessages(messages.clone()),
            )
            .unwrap();

            // all verifiers vote
            let vote_msg = ExecuteMsg::Vote {
                poll_id: Uint64::one().into(),
                votes: vec![consensus_vote.clone(); messages.len()],
            };
            verifiers.iter().for_each(|verifier| {
                execute(
                    deps.as_mut(),
                    mock_env(),
                    mock_info(verifier.address.as_str(), &[]),
                    vote_msg.clone(),
                )
                .unwrap();
            });

            // end poll
            execute(
                deps.as_mut(),
                mock_env_expired(),
                mock_info(SENDER, &[]),
                ExecuteMsg::EndPoll {
                    poll_id: Uint64::one().into(),
                },
            )
            .unwrap();

            // check status corresponds to votes
            let statuses: Vec<MessageStatus> = from_json(
                &query(
                    deps.as_ref(),
                    mock_env(),
                    QueryMsg::MessagesStatus(messages.clone()),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(statuses, msgs_statuses(messages.clone(), *expected_status));
        }
    }

    #[test]
    fn should_be_able_to_update_threshold_and_then_query_new_threshold() {
        let verifiers = verifiers(2);
        let mut deps = setup(verifiers.clone());

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

        let res = query(deps.as_ref(), mock_env(), QueryMsg::CurrentThreshold).unwrap();

        let threshold: MajorityThreshold = from_json(res).unwrap();
        assert_eq!(threshold, new_voting_threshold);
    }

    #[test]
    fn threshold_changes_should_not_affect_existing_polls() {
        let verifiers = verifiers(10);
        let initial_threshold = initial_voting_threshold();
        let majority = (verifiers.len() as u64 * initial_threshold.numerator().u64())
            .div_ceil(initial_threshold.denominator().u64());

        let mut deps = setup(verifiers.clone());

        let messages = messages(1);

        execute(
            deps.as_mut(),
            mock_env(),
            mock_info(SENDER, &[]),
            ExecuteMsg::VerifyMessages(messages.clone()),
        )
        .unwrap();

        // simulate a majority of verifiers voting for succeeded on chain
        verifiers.iter().enumerate().for_each(|(i, verifier)| {
            if i as u64 >= majority {
                return;
            }
            let msg = ExecuteMsg::Vote {
                poll_id: 1u64.into(),
                votes: vec![Vote::SucceededOnChain],
            };

            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(verifier.address.as_str(), &[]),
                msg,
            );
            assert!(res.is_ok());
        });

        // increase the threshold. Not enough verifiers voted to meet the new majority,
        // but threshold changes should not affect existing polls
        let new_voting_threshold: MajorityThreshold =
            Threshold::try_from((majority + 1, verifiers.len() as u64))
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

        let res: Vec<MessageStatus> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::MessagesStatus(messages.clone()),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            res,
            vec![MessageStatus::new(
                messages[0].clone(),
                VerificationStatus::SucceededOnSourceChain
            )]
        );
    }

    #[test]
    fn threshold_changes_should_affect_new_polls() {
        let verifiers = verifiers(10);
        let initial_threshold = initial_voting_threshold();
        let old_majority = (verifiers.len() as u64 * initial_threshold.numerator().u64())
            .div_ceil(initial_threshold.denominator().u64());

        let mut deps = setup(verifiers.clone());

        // increase the threshold prior to starting a poll
        let new_voting_threshold: MajorityThreshold =
            Threshold::try_from((old_majority + 1, verifiers.len() as u64))
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
            ExecuteMsg::VerifyMessages(messages.clone()),
        )
        .unwrap();

        // simulate old_majority of verifiers voting succeeded on chain,
        // which is one less than the updated majority. The messages
        // should not receive enough votes to be considered verified
        verifiers.iter().enumerate().for_each(|(i, verifier)| {
            if i as u64 >= old_majority {
                return;
            }
            let msg = ExecuteMsg::Vote {
                poll_id: 1u64.into(),
                votes: vec![Vote::SucceededOnChain],
            };

            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(verifier.address.as_str(), &[]),
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

        let res: Vec<MessageStatus> = from_json(
            query(
                deps.as_ref(),
                mock_env_expired(),
                QueryMsg::MessagesStatus(messages.clone()),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            res,
            vec![MessageStatus::new(
                messages[0].clone(),
                VerificationStatus::FailedToVerify
            )]
        );
    }

    #[test]
    fn should_emit_event_when_verification_succeeds() {
        let verifiers = verifiers(3);
        let mut deps = setup(verifiers.clone());
        let threshold = initial_voting_threshold();
        // this test depends on the threshold being 2/3
        assert_eq!(
            threshold,
            Threshold::try_from((2, 3)).unwrap().try_into().unwrap()
        );

        let messages = messages(3);

        // 1. First verification

        let msg_verify = ExecuteMsg::VerifyMessages(messages.clone());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(SENDER, &[]),
            msg_verify.clone(),
        );
        assert!(res.is_ok());

        // 2. Verifiers cast votes
        // The first message reaches quorum after 2 votes,
        // The second message reaches quorum after 3 votes,
        // The third message never reaches quorum
        verifiers.iter().enumerate().for_each(|(i, verifier)| {
            let msg = ExecuteMsg::Vote {
                poll_id: 1u64.into(),
                votes: vec![
                    Vote::SucceededOnChain,
                    if i % 2 == 0 {
                        Vote::NotFound
                    } else {
                        Vote::SucceededOnChain
                    },
                    if i % 3 == 0 {
                        Vote::NotFound
                    } else if i % 3 == 1 {
                        Vote::SucceededOnChain
                    } else {
                        Vote::FailedOnChain
                    },
                ],
            };

            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(verifier.address.as_str(), &[]),
                msg,
            )
            .unwrap();

            let verify_event =
                |res: &Response, expected_message: XRPLMessage, expected_status: VerificationStatus| {
                    let mut iter = res.events.iter();

                    let event = iter.find(|event| event.ty == "quorum_reached").unwrap();

                    let msg: XRPLMessage = serde_json::from_str(
                        &event
                            .attributes
                            .iter()
                            .find(|attr| attr.key == "content")
                            .unwrap()
                            .value,
                    )
                    .unwrap();
                    assert_eq!(msg, expected_message);

                    let status: VerificationStatus = serde_json::from_str(
                        &event
                            .attributes
                            .iter()
                            .find(|attr| attr.key == "status")
                            .unwrap()
                            .value,
                    )
                    .unwrap();
                    assert_eq!(status, expected_status);

                    let additional_event = iter.find(|event| event.ty == "quorum_reached");
                    assert_eq!(additional_event, None);
                };

            if i == 0 {
                let event = res.events.iter().find(|event| event.ty == "quorum_reached");
                assert_eq!(event, None);
            }

            if i == 1 {
                verify_event(
                    &res,
                    messages[0].clone(),
                    VerificationStatus::SucceededOnSourceChain,
                );
            }

            if i == 2 {
                verify_event(
                    &res,
                    messages[1].clone(),
                    VerificationStatus::NotFoundOnSourceChain,
                );
            }
        });
    }
}
