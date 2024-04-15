use axelar_wasm_std::{
    operators::Operators, voting::PollId, MajorityThreshold, VerificationStatus,
};
use connection_router_api::{CrossChainId, Message};
use cosmwasm_std::Addr;
use error_stack::ResultExt;

use crate::msg::{ExecuteMsg, Poll, QueryMsg};

type Result<T> = error_stack::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed quering the voting verifier contract at {0}")]
    QueryVotingVerifier(Addr),
}

impl<'a> From<client::Client<'a, ExecuteMsg, QueryMsg>> for Client<'a> {
    fn from(client: client::Client<'a, ExecuteMsg, QueryMsg>) -> Self {
        Client { client }
    }
}

pub struct Client<'a> {
    client: client::Client<'a, ExecuteMsg, QueryMsg>,
}

impl<'a> Client<'a> {
    pub fn poll(&self, poll_id: PollId) -> Result<Poll> {
        self.client
            .query(&QueryMsg::GetPoll { poll_id })
            .change_context_lazy(|| Error::QueryVotingVerifier(self.client.address.clone()))
    }

    pub fn messages_status(
        &self,
        messages: Vec<Message>,
    ) -> Result<Vec<(CrossChainId, VerificationStatus)>> {
        match messages.as_slice() {
            [] => Ok(vec![]),
            _ => self
                .client
                .query(&QueryMsg::GetMessagesStatus { messages })
                .change_context_lazy(|| Error::QueryVotingVerifier(self.client.address.clone())),
        }
    }

    pub fn worker_set_status(&self, new_operators: Operators) -> Result<VerificationStatus> {
        self.client
            .query(&QueryMsg::GetWorkerSetStatus { new_operators })
            .change_context_lazy(|| Error::QueryVotingVerifier(self.client.address.clone()))
    }

    pub fn current_threshold(&self) -> Result<MajorityThreshold> {
        self.client
            .query(&QueryMsg::GetCurrentThreshold)
            .change_context_lazy(|| Error::QueryVotingVerifier(self.client.address.clone()))
    }
}

#[cfg(test)]
mod test {
    use axelar_wasm_std::{operators::Operators, Threshold, VerificationStatus};
    use connection_router_api::{Message, CHAIN_NAME_DELIMITER};
    use cosmwasm_std::{
        from_binary,
        testing::{mock_dependencies, mock_env, mock_info, MockQuerier},
        Addr, DepsMut, QuerierWrapper, Uint256, Uint64, WasmQuery,
    };

    use crate::{
        contract::{instantiate, query},
        msg::{InstantiateMsg, QueryMsg},
        Client,
    };

    #[test]
    fn query_messages_status() {
        let (querier, _, addr) = setup();
        let client: Client = client::Client::new(QuerierWrapper::new(&querier), addr).into();

        let msg_1 = Message {
            cc_id: format!("eth{}0x1234", CHAIN_NAME_DELIMITER)
                .as_str()
                .parse()
                .unwrap(),
            source_address: "0x1234".parse().unwrap(),
            destination_address: "0x5678".parse().unwrap(),
            destination_chain: "eth".parse().unwrap(),
            payload_hash: [0; 32],
        };
        let msg_2 = Message {
            cc_id: format!("eth{}0x4321", CHAIN_NAME_DELIMITER)
                .as_str()
                .parse()
                .unwrap(),
            source_address: "0x4321".parse().unwrap(),
            destination_address: "0x8765".parse().unwrap(),
            destination_chain: "eth".parse().unwrap(),
            payload_hash: [0; 32],
        };

        assert!(client.messages_status(vec![]).unwrap().is_empty());
        assert_eq!(
            client
                .messages_status(vec![msg_1.clone(), msg_2.clone()])
                .unwrap(),
            vec![
                (msg_1.cc_id, VerificationStatus::None),
                (msg_2.cc_id, VerificationStatus::None)
            ]
        );
    }

    #[test]
    fn query_worker_set_status() {
        let (querier, _, addr) = setup();
        let client: Client = client::Client::new(QuerierWrapper::new(&querier), addr).into();

        assert_eq!(
            client
                .worker_set_status(Operators::new(vec![], Uint256::one()))
                .unwrap(),
            VerificationStatus::None
        );
    }

    #[test]
    fn query_current_threshold() {
        let (querier, instantiate_msg, addr) = setup();
        let client: Client = client::Client::new(QuerierWrapper::new(&querier), addr).into();

        assert_eq!(
            client.current_threshold().unwrap(),
            instantiate_msg.voting_threshold
        );
    }

    fn setup() -> (MockQuerier, InstantiateMsg, Addr) {
        let addr = "voting-verifier";
        let mut deps = mock_dependencies();
        let instantiate_msg = instantiate_contract(deps.as_mut());

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart { contract_addr, msg } if contract_addr == addr => {
                let msg = from_binary::<QueryMsg>(msg).unwrap();
                Ok(query(deps.as_ref(), mock_env(), msg).into()).into()
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        (querier, instantiate_msg, Addr::unchecked(addr))
    }

    fn instantiate_contract(deps: DepsMut) -> InstantiateMsg {
        let env = mock_env();
        let info = mock_info("deployer", &[]);

        let msg = InstantiateMsg {
            governance_address: "governance".try_into().unwrap(),
            service_registry_address: "service-registry".try_into().unwrap(),
            service_name: "voting-verifier".try_into().unwrap(),
            source_gateway_address: "source-gateway".try_into().unwrap(),
            voting_threshold: Threshold::try_from((Uint64::new(2), Uint64::new(3)))
                .unwrap()
                .try_into()
                .unwrap(),
            block_expiry: 100,
            confirmation_height: 10,
            source_chain: "source-chain".parse().unwrap(),
            rewards_address: "rewards".to_string(),
        };

        instantiate(deps, env, info.clone(), msg.clone()).unwrap();

        msg
    }
}
