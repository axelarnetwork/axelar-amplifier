use axelar_wasm_std::vec::VecExt;
use axelar_wasm_std::voting::{PollId, Vote};
use axelar_wasm_std::{nonempty, MajorityThreshold, VerificationStatus};
use cosmwasm_std::{Addr, WasmMsg};
use error_stack::ResultExt;
use multisig::verifier_set::VerifierSet;
use router_api::Message;

use crate::msg::{ExecuteMsg, MessageStatus, PollResponse, QueryMsg};

type Result<T> = error_stack::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to query the voting verifier contract at {0}")]
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
    pub fn verify_messages(&self, messages: Vec<Message>) -> Option<WasmMsg> {
        messages
            .to_none_if_empty()
            .map(|messages| self.client.execute(&ExecuteMsg::VerifyMessages(messages)))
    }

    pub fn vote(&self, poll_id: PollId, votes: Vec<Vote>) -> WasmMsg {
        self.client.execute(&ExecuteMsg::Vote { poll_id, votes })
    }

    pub fn end_poll(&self, poll_id: PollId) -> WasmMsg {
        self.client.execute(&ExecuteMsg::EndPoll { poll_id })
    }

    pub fn verify_verifier_set(
        &self,
        message_id: nonempty::String,
        new_verifier_set: VerifierSet,
    ) -> WasmMsg {
        self.client.execute(&ExecuteMsg::VerifyVerifierSet {
            message_id,
            new_verifier_set,
        })
    }

    pub fn update_voting_threshold(&self, new_voting_threshold: MajorityThreshold) -> WasmMsg {
        self.client.execute(&ExecuteMsg::UpdateVotingThreshold {
            new_voting_threshold,
        })
    }

    pub fn poll(&self, poll_id: PollId) -> Result<PollResponse> {
        self.client
            .query(&QueryMsg::Poll { poll_id })
            .change_context_lazy(|| Error::QueryVotingVerifier(self.client.address.clone()))
    }

    pub fn messages_status(&self, messages: Vec<Message>) -> Result<Vec<MessageStatus>> {
        match messages.as_slice() {
            [] => Ok(vec![]),
            _ => self
                .client
                .query(&QueryMsg::MessagesStatus(messages))
                .change_context_lazy(|| Error::QueryVotingVerifier(self.client.address.clone())),
        }
    }

    pub fn verifier_set_status(&self, new_verifier_set: VerifierSet) -> Result<VerificationStatus> {
        self.client
            .query(&QueryMsg::VerifierSetStatus(new_verifier_set))
            .change_context_lazy(|| Error::QueryVotingVerifier(self.client.address.clone()))
    }

    pub fn current_threshold(&self) -> Result<MajorityThreshold> {
        self.client
            .query(&QueryMsg::CurrentThreshold)
            .change_context_lazy(|| Error::QueryVotingVerifier(self.client.address.clone()))
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelar_wasm_std::{Threshold, VerificationStatus};
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info, MockQuerier};
    use cosmwasm_std::{from_json, Addr, DepsMut, QuerierWrapper, Uint128, Uint64, WasmQuery};
    use multisig::verifier_set::VerifierSet;
    use router_api::{CrossChainId, Message};

    use crate::contract::{instantiate, query};
    use crate::msg::{InstantiateMsg, MessageStatus, QueryMsg};
    use crate::Client;

    #[test]
    fn query_messages_status() {
        let (querier, _, addr) = setup();
        let client: Client = client::Client::new(QuerierWrapper::new(&querier), addr).into();

        let msg_1 = Message {
            cc_id: CrossChainId::new(
                "eth",
                HexTxHashAndEventIndex {
                    tx_hash: [0; 32],
                    event_index: 0,
                }
                .to_string()
                .as_str(),
            )
            .unwrap(),
            source_address: "0x1234".parse().unwrap(),
            destination_address: "0x5678".parse().unwrap(),
            destination_chain: "eth".parse().unwrap(),
            payload_hash: [0; 32],
        };
        let msg_2 = Message {
            cc_id: CrossChainId::new(
                "eth",
                HexTxHashAndEventIndex {
                    tx_hash: [1; 32],
                    event_index: 0,
                }
                .to_string()
                .as_str(),
            )
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
                MessageStatus::new(msg_1, VerificationStatus::Unknown),
                MessageStatus::new(msg_2, VerificationStatus::Unknown)
            ]
        );
    }

    #[test]
    fn query_verifier_set_status() {
        let (querier, _, addr) = setup();
        let client: Client = client::Client::new(QuerierWrapper::new(&querier), addr).into();

        assert_eq!(
            client
                .verifier_set_status(VerifierSet {
                    signers: BTreeMap::new(),
                    threshold: Uint128::one(),
                    created_at: 0
                })
                .unwrap(),
            VerificationStatus::Unknown
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
                let msg = from_json::<QueryMsg>(msg).unwrap();
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
            block_expiry: 100.try_into().unwrap(),
            confirmation_height: 10,
            source_chain: "source-chain".parse().unwrap(),
            rewards_address: "rewards".try_into().unwrap(),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
            address_format: axelar_wasm_std::address::AddressFormat::Eip55,
        };

        instantiate(deps, env, info.clone(), msg.clone()).unwrap();

        msg
    }
}
