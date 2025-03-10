use axelar_wasm_std::vec::VecExt;
use axelar_wasm_std::voting::{PollId, Vote};
use axelar_wasm_std::MajorityThreshold;
use cosmwasm_std::CosmosMsg;
use error_stack::ResultExt;
use xrpl_types::msg::XRPLMessage;

use crate::msg::{ExecuteMsg, MessageStatus, PollResponse, QueryMsg};

type Result<T> = error_stack::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to query xrpl voting verifier for current voting threshold")]
    CurrentThreshold,
    #[error("failed to query xrpl voting verifier for messages status. messages: {0:?}")]
    MessagesStatus(Vec<XRPLMessage>),
    #[error("failed to query xrpl voting verifier for poll. poll_id: {0}")]
    Poll(PollId),
}

impl From<QueryMsg> for Error {
    fn from(value: QueryMsg) -> Self {
        match value {
            QueryMsg::MessagesStatus(messages) => Error::MessagesStatus(messages),
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
    pub fn verify_messages(&self, messages: Vec<XRPLMessage>) -> Option<CosmosMsg> {
        messages
            .to_none_if_empty()
            .map(|messages| self.client.execute(&ExecuteMsg::VerifyMessages(messages)))
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
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }

    pub fn messages_status(&self, messages: Vec<XRPLMessage>) -> Result<Vec<MessageStatus>> {
        match messages.as_slice() {
            [] => Ok(vec![]),
            _ => {
                let msg = QueryMsg::MessagesStatus(messages);
                self.client.query(&msg).change_context_lazy(|| msg.into())
            }
        }
    }

    pub fn current_threshold(&self) -> Result<MajorityThreshold> {
        let msg = QueryMsg::CurrentThreshold;
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }
}

#[cfg(test)]
mod test {
    use axelar_wasm_std::msg_id::HexTxHash;
    use axelar_wasm_std::{nonempty, Threshold, VerificationStatus};
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env, MockApi, MockQuerier};
    use cosmwasm_std::{from_json, Addr, DepsMut, QuerierWrapper, SystemError, Uint64, WasmQuery};
    use xrpl_types::msg::{XRPLMessage, XRPLUserMessage};
    use xrpl_types::types::{XRPLAccountId, XRPLPaymentAmount, XRPLToken, XRPLTokenAmount};

    use crate::contract::{instantiate, query};
    use crate::msg::{InstantiateMsg, MessageStatus, QueryMsg};
    use crate::Client;

    #[test]
    fn query_messages_status() {
        let (querier, _, addr) = setup();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        let msg_1 = XRPLMessage::UserMessage(XRPLUserMessage {
            tx_id: HexTxHash::new([0; 32]),
            source_address: XRPLAccountId::new([0; 20]),
            destination_address: nonempty::String::try_from("5678").unwrap(),
            destination_chain: "eth".parse().unwrap(),
            payload_hash: None,
            amount: XRPLPaymentAmount::Drops(100),
            gas_fee_amount: XRPLPaymentAmount::Drops(100),
        });

        let msg_2 = XRPLMessage::UserMessage(XRPLUserMessage {
            tx_id: HexTxHash::new([1; 32]),
            source_address: XRPLAccountId::new([1; 20]),
            destination_address: nonempty::String::try_from("5678").unwrap(),
            destination_chain: "eth".parse().unwrap(),
            payload_hash: None,
            amount: XRPLPaymentAmount::Issued(
                XRPLToken {
                    currency: "USD".to_string().try_into().unwrap(),
                    issuer: XRPLAccountId::new([0; 20]),
                },
                XRPLTokenAmount::try_from("1e15".to_string()).unwrap(),
            ),
            gas_fee_amount: XRPLPaymentAmount::Issued(
                XRPLToken {
                    currency: "USD".to_string().try_into().unwrap(),
                    issuer: XRPLAccountId::new([0; 20]),
                },
                XRPLTokenAmount::try_from("100".to_string()).unwrap(),
            ),
        });

        assert!(client.messages_status(vec![]).unwrap().is_empty());
        assert_eq!(
            client
                .messages_status(vec![msg_1.clone(), msg_2.clone()])
                .unwrap(),
            vec![
                MessageStatus::new(msg_1, VerificationStatus::Unknown),
                MessageStatus::new(msg_2, VerificationStatus::Unknown)
            ]
        );
    }

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
    fn query_messages_status_returns_error_when_query_fails() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.messages_status(vec![XRPLMessage::UserMessage(XRPLUserMessage {
            tx_id: HexTxHash::new([0; 32]),
            source_address: XRPLAccountId::new([255; 20]),
            destination_address: nonempty::String::try_from("5678").unwrap(),
            destination_chain: "eth".parse().unwrap(),
            payload_hash: None,
            amount: XRPLPaymentAmount::Drops(200),
            gas_fee_amount: XRPLPaymentAmount::Drops(200),
        })]);

        assert!(res.is_err());
        goldie::assert!(res.unwrap_err().to_string());
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
        let addr = "voting-verifier";

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart {
                contract_addr,
                msg: _,
            } if contract_addr == addr => {
                Err(SystemError::Unknown {}).into() // simulate cryptic error seen in production
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        (querier, Addr::unchecked(addr))
    }

    fn setup() -> (MockQuerier, InstantiateMsg, Addr) {
        let addr = "voting-verifier";
        let mut deps = mock_dependencies();
        let instantiate_msg = instantiate_contract(deps.as_mut());

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart { contract_addr, msg } if contract_addr == addr => {
                let msg = from_json::<QueryMsg>(msg).unwrap();
                Ok(query(deps.as_ref(), mock_env(), msg).into()).into()
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        (querier, instantiate_msg, Addr::unchecked(addr))
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
            service_name: "voting-verifier".try_into().unwrap(),
            source_gateway_address: "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
                .to_string()
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
        };

        instantiate(deps, env, info.clone(), msg.clone()).unwrap();

        msg
    }
}
