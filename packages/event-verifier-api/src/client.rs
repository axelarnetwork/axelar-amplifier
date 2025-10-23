use axelar_wasm_std::voting::{PollId, Vote};
use axelar_wasm_std::MajorityThreshold;
use cosmwasm_std::CosmosMsg;
use error_stack::ResultExt;

use crate::msg::{EventStatus, EventToVerify, ExecuteMsg, PollResponse, QueryMsg};

type Result<T> = error_stack::Result<T, Error>;

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("failed to query event verifier for poll {0}")]
    Poll(PollId),

    #[error("failed to query event verifier for events status")]
    EventsStatus,

    #[error("failed to query event verifier for current threshold")]
    CurrentThreshold,
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
    pub fn vote(&self, poll_id: PollId, votes: Vec<Vote>) -> CosmosMsg {
        self.client.execute(&ExecuteMsg::Vote { poll_id, votes })
    }

    pub fn verify_events(&self, events: Vec<EventToVerify>) -> CosmosMsg {
        self.client.execute(&ExecuteMsg::VerifyEvents(events))
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
            .change_context_lazy(|| Error::Poll(poll_id))
    }

    pub fn events_status(&self, events: Vec<EventToVerify>) -> Result<Vec<EventStatus>> {
        let msg = QueryMsg::EventsStatus(events);
        self.client.query(&msg).change_context(Error::EventsStatus)
    }

    pub fn current_threshold(&self) -> Result<MajorityThreshold> {
        let msg = QueryMsg::CurrentThreshold;
        self.client
            .query(&msg)
            .change_context(Error::CurrentThreshold)
    }
}

#[cfg(test)]
mod test {
    use axelar_wasm_std::snapshot::{Participant, Snapshot};
    use axelar_wasm_std::voting::{PollId, PollStatus, WeightedPoll};
    use axelar_wasm_std::{chain_name, nonempty, MajorityThreshold, Threshold, VerificationStatus};
    use cosmwasm_std::testing::{MockApi, MockQuerier};
    use cosmwasm_std::{
        from_json, to_json_binary, Addr, QuerierWrapper, SystemError, Uint128, WasmQuery,
    };

    use crate::client::Client;
    use crate::msg::{EventStatus, EventToVerify, PollData, PollResponse, QueryMsg};

    const ETHEREUM: &str = "ethereum";

    #[test]
    fn query_poll_returns_error_when_query_fails() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let poll_id = PollId::from(100u64);
        let res = client.poll(poll_id);

        assert!(res.is_err(), "{:?}", res.unwrap());
        goldie::assert!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_poll_returns_poll() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let poll_id = PollId::from(100u64);
        let res = client.poll(poll_id);

        assert!(res.is_ok(), "{}", res.unwrap_err().to_string());
        goldie::assert_json!(res.unwrap());
    }

    #[test]
    fn query_events_status_returns_error_when_query_fails() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let events = vec![EventToVerify {
            source_chain: chain_name!(ETHEREUM),
            event_data: "{}".to_string(),
        }];
        let res = client.events_status(events);

        assert!(res.is_err(), "{:?}", res.unwrap());
        goldie::assert!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_events_status_returns_status() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let events = vec![EventToVerify {
            source_chain: chain_name!(ETHEREUM),
            event_data: "{}".to_string(),
        }];
        let res = client.events_status(events);

        assert!(res.is_ok(), "{}", res.unwrap_err().to_string());
        goldie::assert_json!(res.unwrap());
    }

    #[test]
    fn query_current_threshold_returns_error_when_query_fails() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.current_threshold();

        assert!(res.is_err(), "{:?}", res.unwrap());
        goldie::assert!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_current_threshold_returns_threshold() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.current_threshold();

        assert!(res.is_ok(), "{}", res.unwrap_err().to_string());
        goldie::assert_json!(res.unwrap());
    }

    fn setup_queries_to_fail() -> (MockQuerier, Addr) {
        let addr = MockApi::default().addr_make("event-verifier");
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

    fn mock_poll(poll_id: PollId) -> PollResponse {
        let api = MockApi::default();
        let participant = Participant {
            address: api.addr_make("participant"),
            weight: nonempty::Uint128::try_from(Uint128::one()).unwrap(),
        };
        let participants = nonempty::Vec::try_from(vec![participant]).unwrap();
        let threshold: MajorityThreshold = Threshold::try_from((2u64, 3u64))
            .unwrap()
            .try_into()
            .unwrap();
        let snapshot = Snapshot::new(threshold, participants);

        let poll = WeightedPoll::new(poll_id, snapshot, 1000, 1);

        PollResponse {
            poll,
            data: PollData {
                events: vec![EventToVerify {
                    source_chain: chain_name!(ETHEREUM),
                    event_data: "{}".to_string(),
                }],
            },
            status: PollStatus::InProgress,
        }
    }

    fn setup_queries_to_succeed() -> (MockQuerier, Addr) {
        let addr = MockApi::default().addr_make("event-verifier");
        let addr_clone = addr.clone();

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart { contract_addr, msg } if contract_addr == addr.as_str() => {
                let msg = from_json::<QueryMsg>(msg).unwrap();
                match msg {
                    QueryMsg::Poll { poll_id } => {
                        Ok(to_json_binary(&mock_poll(poll_id)).into()).into()
                    }
                    QueryMsg::EventsStatus(events) => {
                        let statuses: Vec<EventStatus> = events
                            .into_iter()
                            .map(|event| EventStatus {
                                event,
                                status: VerificationStatus::SucceededOnSourceChain,
                            })
                            .collect();
                        Ok(to_json_binary(&statuses).into()).into()
                    }
                    QueryMsg::CurrentThreshold => {
                        let threshold: MajorityThreshold = Threshold::try_from((2u64, 3u64))
                            .unwrap()
                            .try_into()
                            .unwrap();
                        Ok(to_json_binary(&threshold).into()).into()
                    }
                }
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        (querier, addr_clone)
    }
}
