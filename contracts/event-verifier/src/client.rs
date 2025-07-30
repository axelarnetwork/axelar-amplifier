use axelar_wasm_std::vec::VecExt;
use axelar_wasm_std::voting::{PollId, Vote};
use axelar_wasm_std::MajorityThreshold;
use cosmwasm_std::CosmosMsg;
use error_stack::ResultExt;

use crate::msg::{EventStatus, EventToVerify, ExecuteMsg, PollResponse, QueryMsg};

type Result<T> = error_stack::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to query voting verifier for current voting threshold")]
    CurrentThreshold,
    #[error("failed to query voting verifier for events status. events: {0:?}")]
    EventsStatus(Vec<EventToVerify>),
    #[error("failed to query voting verifier for poll. poll_id: {0}")]
    Poll(PollId),
}

impl Error {
    fn for_query(value: QueryMsg) -> Self {
        match value {
            QueryMsg::EventsStatus(events) => Error::EventsStatus(events),
            QueryMsg::Poll { poll_id } => Error::Poll(poll_id),
            QueryMsg::CurrentThreshold => Error::CurrentThreshold,
        }
    }
}

impl<'a> From<client::ContractClient<'a, ExecuteMsg, QueryMsg>> for Client<'a> {
    fn from(client: client::ContractClient<'a, ExecuteMsg, QueryMsg>) -> Self {
        Client { client }
    }
}

pub struct Client<'a> {
    client: client::ContractClient<'a, ExecuteMsg, QueryMsg>,
}

impl Client<'_> {
    pub fn verify_events(&self, events: Vec<crate::msg::EventToVerify>) -> Option<CosmosMsg> {
        events
            .to_none_if_empty()
            .map(|events| self.client.execute(&ExecuteMsg::VerifyEvents(events)))
    }

    pub fn vote(&self, poll_id: PollId, votes: Vec<Vote>) -> CosmosMsg {
        self.client.execute(&ExecuteMsg::Vote { poll_id, votes })
    }

    pub fn end_poll(&self, poll_id: PollId) -> CosmosMsg {
        self.client.execute(&ExecuteMsg::EndPoll { poll_id })
    }

    pub fn update_voting_threshold(&self, new_voting_threshold: MajorityThreshold) -> CosmosMsg {
        self.client.execute(&ExecuteMsg::UpdateVotingThreshold {
            new_voting_threshold,
        })
    }

    pub fn poll(&self, poll_id: PollId) -> Result<PollResponse> {
        let msg = QueryMsg::Poll { poll_id };
        self.client
            .query(&msg)
            .change_context_lazy(|| Error::for_query(msg))
    }

    pub fn events_status(&self, events: Vec<EventToVerify>) -> Result<Vec<EventStatus>> {
        match events.as_slice() {
            [] => Ok(vec![]),
            _ => {
                let msg = QueryMsg::EventsStatus(events);
                self.client
                    .query(&msg)
                    .change_context_lazy(|| Error::for_query(msg))
            }
        }
    }

    pub fn current_threshold(&self) -> Result<MajorityThreshold> {
        let msg = QueryMsg::CurrentThreshold;
        self.client
            .query(&msg)
            .change_context_lazy(|| Error::for_query(msg))
    }
}

#[cfg(test)]
mod test {
    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelar_wasm_std::{Threshold, VerificationStatus};
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env, MockApi, MockQuerier};
    use cosmwasm_std::{from_json, Addr, DepsMut, QuerierWrapper, SystemError, Uint64, WasmQuery};
    use router_api::{CrossChainId, Message};

    use crate::contract::{instantiate, query};
    use crate::msg::{InstantiateMsg, QueryMsg};
    use crate::Client;

    // Message status tests removed - message functionality has been removed from event-verifier

    #[test]
    fn query_current_threshold() {
        let (querier, instantiate_msg, addr) = setup();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        assert_eq!(
            client.current_threshold().unwrap(),
            instantiate_msg.voting_threshold
        );
    }

    #[test]
    fn query_poll_returns_error_when_query_fails() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.poll(1u64.into());

        assert!(res.is_err());
        goldie::assert!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_current_threshold_returns_error_when_query_fails() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.current_threshold();

        assert!(res.is_err());
        goldie::assert!(res.unwrap_err().to_string());
    }

    fn setup_queries_to_fail() -> (MockQuerier, Addr) {
        let deps = mock_dependencies();
        let api: MockApi = deps.api;
        let addr = api.addr_make("event-verifier");
        let addr_clone = addr.clone();

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart {
                contract_addr,
                msg: _,
            } if contract_addr == addr.as_str() => {
                Err(SystemError::Unknown {}).into() // simulate cryptic error seen in production
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        (querier, addr_clone)
    }

    fn setup() -> (MockQuerier, InstantiateMsg, Addr) {
        let mut deps = mock_dependencies();
        let api = deps.api;
        let addr = api.addr_make("event-verifier");
        let addr_clone = addr.clone();
        let instantiate_msg = instantiate_contract(deps.as_mut());

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart { contract_addr, msg } if contract_addr == addr.as_str() => {
                let msg = from_json::<QueryMsg>(msg).unwrap();
                Ok(query(deps.as_ref(), mock_env(), msg).into()).into()
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        (querier, instantiate_msg, addr_clone)
    }

    fn instantiate_contract(deps: DepsMut) -> InstantiateMsg {
        let env = mock_env();
        let api = MockApi::default();
        let info = message_info(&api.addr_make("deployer"), &[]);

        let msg = InstantiateMsg {
            governance_address: api.addr_make("governance").to_string().try_into().unwrap(),
            service_registry_address: api
                .addr_make("service-registry")
                .to_string()
                .try_into()
                .unwrap(),
            service_name: "event-verifier".try_into().unwrap(),
            source_gateway_address: "0x4F4495243837681061C4743b74B3eEdf548D56A5"
                .try_into()
                .unwrap(),
            voting_threshold: Threshold::try_from((Uint64::new(2), Uint64::new(3)))
                .unwrap()
                .try_into()
                .unwrap(),
            block_expiry: 100.try_into().unwrap(),
            confirmation_height: 10,
            source_chain: "source-chain".parse().unwrap(),
            rewards_address: api.addr_make("rewards").to_string().try_into().unwrap(),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
            address_format: axelar_wasm_std::address::AddressFormat::Eip55,
        };

        instantiate(deps, env, info.clone(), msg.clone()).unwrap();

        msg
    }
}
