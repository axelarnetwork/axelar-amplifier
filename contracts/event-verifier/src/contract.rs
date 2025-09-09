use axelar_wasm_std::{address, permission_control, FnExt};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Attribute, Binary, Deps, DepsMut, Env, Event, MessageInfo, Response,
};
use error_stack::ResultExt;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{Config, CONFIG};

mod execute;
mod migrations;
mod query;

pub use migrations::{migrate, MigrateMsg};

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
    let admin = address::validate_cosmwasm_address(deps.api, &msg.admin_address)?;
    permission_control::set_admin(deps.storage, &admin)?;



    let config = Config {
        service_name: msg.service_name,
        service_registry_contract: address::validate_cosmwasm_address(
            deps.api,
            &msg.service_registry_address,
        )?,
        admin: address::validate_cosmwasm_address(deps.api, &msg.admin_address)?,
        voting_threshold: msg.voting_threshold,
        block_expiry: msg.block_expiry,
        fee: msg.fee,
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
        ExecuteMsg::VerifyEvents(events) => Ok(execute::verify_events(deps, env, info, events)?),
        ExecuteMsg::Vote { poll_id, votes } => Ok(execute::vote(deps, env, info, poll_id, votes)?),
        ExecuteMsg::UpdateVotingThreshold {
            new_voting_threshold,
        } => Ok(execute::update_voting_threshold(
            deps,
            new_voting_threshold,
        )?),
        ExecuteMsg::UpdateFee { new_fee } => Ok(execute::update_fee(deps, info, new_fee)?),
        ExecuteMsg::Withdraw { receiver } => Ok(execute::withdraw(deps, env, info, receiver)?),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps,
    env: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::error::ContractError> {
    match msg {
        QueryMsg::Poll { poll_id } => {
            to_json_binary(&query::poll_response(deps, env.block.height, poll_id)?)
        }
        QueryMsg::EventsStatus(events) => {
            to_json_binary(&query::events_status(deps, &events, env.block.height)?)
        }
        QueryMsg::CurrentThreshold => to_json_binary(&query::voting_threshold(deps)?),
        QueryMsg::CurrentFee => to_json_binary(&query::current_fee(deps)?),
    }?
    .then(Ok)
}

#[cfg(test)]
mod test {
    use axelar_wasm_std::{nonempty, MajorityThreshold, Threshold, VerificationStatus};
    use axelar_wasm_std::voting::Vote;
    use cosmwasm_std::testing::{
        message_info, mock_dependencies, mock_env, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{from_json, Empty, OwnedDeps, Uint128, WasmQuery, Fraction, Coin, HexBinary};
    use axelar_wasm_std::voting::PollStatus;
    use crate::msg::{PollResponse, PollData};
    use axelar_wasm_std::fixed_size as fixed;
    use event_verifier_api as evapi;
    use router_api::ChainName;
    use service_registry::{AuthorizationState, BondingState, Verifier, WeightedVerifier};

    use super::*;
    use crate::error::ContractError;
    use crate::msg::EventToVerify;

    const SENDER: &str = "sender";
    const SERVICE_REGISTRY_ADDRESS: &str = "service_registry_address";
    // rewards address removed
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
                address: MockApi::default().addr_make(format!("addr{}", i).as_str()),
                bonding_state: BondingState::Bonded {
                    amount: Uint128::from(100u128).try_into().unwrap(),
                },
                authorization_state: AuthorizationState::Authorized,
                service_name: SERVICE_NAME.parse().unwrap(),
            })
        }
        verifiers
    }

    fn evm_event_json() -> String {
        let tx_hash = fixed::HexBinary::<32>::try_from(vec![0u8; 32]).unwrap();
        let addr = fixed::HexBinary::<20>::try_from(vec![0u8; 20]).unwrap();
        let ev = evapi::Event {
            contract_address: addr,
            event_index: 0,
            topics: vec![],
            data: HexBinary::from(Vec::<u8>::new()),
        };
        let evm = evapi::EvmEvent { transaction_hash: tx_hash, transaction_details: None, events: vec![ev] };
        serde_json::to_string(&evapi::EventData::Evm(evm)).unwrap()
    }

    // Minimal setup for simple execute/query tests
    fn setup(
        verifiers: Vec<Verifier>,
    ) -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = mock_dependencies();
        let api = deps.api;
        let service_registry = api.addr_make(SERVICE_REGISTRY_ADDRESS);

        instantiate(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("admin"), &[]),
            InstantiateMsg {
                governance_address: api.addr_make(GOVERNANCE).as_str().parse().unwrap(),
                service_registry_address: service_registry.as_str().parse().unwrap(),
                service_name: SERVICE_NAME.parse().unwrap(),
                admin_address: api.addr_make(GOVERNANCE).as_str().parse().unwrap(),
                voting_threshold: initial_voting_threshold(),
                block_expiry: POLL_BLOCK_EXPIRY.try_into().unwrap(),
                fee: cosmwasm_std::coin(0, "uaxl"),
            },
        )
        .unwrap();

        deps.querier.update_wasm(move |wq| match wq {
            WasmQuery::Smart { contract_addr, .. }
                if contract_addr == service_registry.as_str() =>
            {
                Ok(to_json_binary(
                    &verifiers
                        .clone()
                        .into_iter()
                        .map(|v| WeightedVerifier {
                            verifier_info: v,
                            weight: nonempty::Uint128::one(),
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

    #[test]
    fn should_be_able_to_update_threshold_and_then_query_new_threshold() {
        let verifiers = verifiers(2);
        let mut deps = setup(verifiers.clone());
        let api = deps.api;

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
            message_info(&api.addr_make(GOVERNANCE), &[]),
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
    fn query_current_fee_should_return_value() {
        let verifiers = verifiers(1);
        let mut deps = setup(verifiers);
        let api = deps.api;

        // initial fee
        let res = query(deps.as_ref(), mock_env(), QueryMsg::CurrentFee).unwrap();
        let fee: Coin = from_json(res).unwrap();
        assert_eq!(fee, cosmwasm_std::coin(0, "uaxl"));

        // update fee and query again
        execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(GOVERNANCE), &[]),
            ExecuteMsg::UpdateFee { new_fee: cosmwasm_std::coin(2, "uaxl") },
        )
        .unwrap();

        let res = query(deps.as_ref(), mock_env(), QueryMsg::CurrentFee).unwrap();
        let fee: Coin = from_json(res).unwrap();
        assert_eq!(fee, cosmwasm_std::coin(2, "uaxl"));
    }

    #[test]
    fn query_events_status_should_return_unknown_for_new_event() {
        let verifiers = verifiers(1);
        let deps = setup(verifiers);

        let event = EventToVerify { source_chain: source_chain(), event_data: evm_event_json() };

        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::EventsStatus(vec![event.clone()]),
        )
        .unwrap();
        let statuses: Vec<crate::msg::EventStatus> = from_json(res).unwrap();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].event, event);
        assert_eq!(statuses[0].status, VerificationStatus::Unknown);
    }

    #[test]
    fn query_events_status_should_be_in_progress_after_verify() {
        let verifiers = verifiers(1);
        let mut deps = setup(verifiers);
        let api = deps.api;

        let event = EventToVerify { source_chain: source_chain(), event_data: evm_event_json() };

        execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(SENDER), &[]),
            ExecuteMsg::VerifyEvents(vec![event.clone()]),
        )
        .unwrap();

        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::EventsStatus(vec![event.clone()]),
        )
        .unwrap();
        let statuses: Vec<crate::msg::EventStatus> = from_json(res).unwrap();
        assert_eq!(statuses[0].status, VerificationStatus::InProgress);
    }

    #[test]
    fn query_events_status_should_be_verified_after_quorum() {
        let verifiers = verifiers(3);
        let mut deps = setup(verifiers);
        let api = deps.api;

        let event = EventToVerify { source_chain: source_chain(), event_data: evm_event_json() };

        // Create poll with single event
        execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(SENDER), &[]),
            ExecuteMsg::VerifyEvents(vec![event.clone()]),
        )
        .unwrap();

        // Two participants vote succeeded (2/3 quorum)
        execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("addr0"), &[]),
            ExecuteMsg::Vote { poll_id: 1u64.into(), votes: vec![Vote::SucceededOnChain] },
        )
        .unwrap();
        execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("addr1"), &[]),
            ExecuteMsg::Vote { poll_id: 1u64.into(), votes: vec![Vote::SucceededOnChain] },
        )
        .unwrap();

        // Status should be SucceededOnSourceChain
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::EventsStatus(vec![event.clone()]),
        )
        .unwrap();
        let statuses: Vec<crate::msg::EventStatus> = from_json(res).unwrap();
        assert_eq!(statuses[0].status, VerificationStatus::SucceededOnSourceChain);
    }

    #[test]
    fn quorum_reached_event_emitted_on_quorum() {
        let verifiers = verifiers(3);
        let mut deps = setup(verifiers);
        let api = deps.api;

        let event = EventToVerify { source_chain: source_chain(), event_data: evm_event_json() };

        // Create poll
        execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(SENDER), &[]),
            ExecuteMsg::VerifyEvents(vec![event]),
        )
        .unwrap();

        // First vote - no quorum yet
        let _ = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("addr0"), &[]),
            ExecuteMsg::Vote { poll_id: 1u64.into(), votes: vec![Vote::SucceededOnChain] },
        )
        .unwrap();

        // Second vote - should reach quorum and emit event
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("addr1"), &[]),
            ExecuteMsg::Vote { poll_id: 1u64.into(), votes: vec![Vote::SucceededOnChain] },
        )
        .unwrap();

        assert!(res.events.iter().any(|e| e.ty == "quorum_reached"));
    }

    #[test]
    fn query_poll_should_return_created_poll() {
        let verifiers = verifiers(1);
        let mut deps = setup(verifiers);
        let api = deps.api;

        // create a poll via verify events
        let event = EventToVerify { source_chain: source_chain(), event_data: evm_event_json() };

        execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(SENDER), &[]),
            ExecuteMsg::VerifyEvents(vec![event]),
        )
        .unwrap();

        // query poll 1
        let res = query(deps.as_ref(), mock_env(), QueryMsg::Poll { poll_id: 1u64.into() })
            .unwrap();
        let poll_res: PollResponse = from_json(res).unwrap();

        assert_eq!(poll_res.poll.poll_id, 1u64.into());
        assert!(matches!(poll_res.status, PollStatus::InProgress));
        match poll_res.data {
            PollData::Events(evts) => assert_eq!(evts.len(), 1),
        }
    }

    #[test]
    fn only_governance_can_update_voting_threshold() {
        let verifiers = verifiers(1);
        let mut deps = setup(verifiers);
        let api = deps.api;

        // Non-governance should be unauthorized
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("not-gov"), &[]),
            ExecuteMsg::UpdateVotingThreshold { new_voting_threshold: initial_voting_threshold() },
        );
        assert!(res.is_err());

        // Governance allowed
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(GOVERNANCE), &[]),
            ExecuteMsg::UpdateVotingThreshold { new_voting_threshold: initial_voting_threshold() },
        );
        assert!(res.is_ok());
    }

    #[test]
    fn only_admin_can_update_fee_and_withdraw() {
        let verifiers = verifiers(1);
        let mut deps = setup(verifiers);
        let api = deps.api;

        // Non-admin should be unauthorized for UpdateFee
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("not-admin"), &[]),
            ExecuteMsg::UpdateFee { new_fee: cosmwasm_std::coin(2, "uaxl") },
        );
        assert!(res.is_err());

        // Admin allowed for UpdateFee
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(GOVERNANCE), &[]),
            ExecuteMsg::UpdateFee { new_fee: cosmwasm_std::coin(2, "uaxl") },
        );
        assert!(res.is_ok());

        // Non-admin should be unauthorized for Withdraw
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("not-admin"), &[]),
            ExecuteMsg::Withdraw { receiver: api.addr_make("rcv").as_str().parse().unwrap() },
        );
        assert!(res.is_err());

        // Admin allowed for Withdraw
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(GOVERNANCE), &[]),
            ExecuteMsg::Withdraw { receiver: api.addr_make("rcv").as_str().parse().unwrap() },
        );
        assert!(res.is_ok());
    }

    fn make_event() -> EventToVerify {
        EventToVerify { source_chain: source_chain(), event_data: evm_event_json() }
    }

    #[test]
    fn anyone_can_verify_events() {
        let verifiers = verifiers(1);
        let mut deps = setup(verifiers);
        let api = deps.api;

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(SENDER), &[]),
            ExecuteMsg::VerifyEvents(vec![make_event()]),
        );
        assert!(res.is_ok());
    }

    #[test]
    fn anyone_can_vote() {
        let verifiers = verifiers(1);
        let mut deps = setup(verifiers);
        let api = deps.api;

        // No poll exists; should not be Unauthorized, but PollNotFound
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(SENDER), &[]),
            ExecuteMsg::Vote { poll_id: 1u64.into(), votes: vec![] },
        );
        assert_eq!(res.unwrap_err().to_string(), ContractError::PollNotFound.to_string());
    }
}
