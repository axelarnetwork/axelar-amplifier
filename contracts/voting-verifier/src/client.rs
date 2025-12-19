use axelar_wasm_std::vec::VecExt;
use axelar_wasm_std::voting::{PollId, Vote};
use axelar_wasm_std::{nonempty, MajorityThreshold, VerificationStatus};
use cosmwasm_std::CosmosMsg;
use error_stack::ResultExt;
use multisig::verifier_set::VerifierSet;
use router_api::Message;

use crate::msg::{ExecuteMsg, MessageStatus, PollResponse, QueryMsg, VotingParameters};

type Result<T> = error_stack::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to query voting verifier for verifier set status. verifier_set: {0:?}")]
    VerifierSetStatus(VerifierSet),
    #[error("failed to query voting verifier for voting parameters")]
    VotingParameters,
    #[error("failed to query voting verifier for messages status. messages: {0:?}")]
    MessagesStatus(Vec<Message>),
    #[error("failed to query voting verifier for poll. poll_id: {0}")]
    Poll(PollId),
}

impl Error {
    fn for_query(value: QueryMsg) -> Self {
        match value {
            QueryMsg::MessagesStatus(messages) => Error::MessagesStatus(messages),
            QueryMsg::VerifierSetStatus(verifier_set) => Error::VerifierSetStatus(verifier_set),
            QueryMsg::Poll { poll_id } => Error::Poll(poll_id),
            QueryMsg::VotingParameters => Error::VotingParameters,
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
    pub fn verify_messages(&self, messages: Vec<Message>) -> Option<CosmosMsg> {
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

    pub fn verify_verifier_set(
        &self,
        message_id: nonempty::String,
        new_verifier_set: VerifierSet,
    ) -> CosmosMsg {
        self.client.execute(&ExecuteMsg::VerifyVerifierSet {
            message_id,
            new_verifier_set,
        })
    }

    pub fn update_voting_parameters(
        &self,
        voting_threshold: Option<MajorityThreshold>,
        block_expiry: Option<nonempty::Uint64>,
        confirmation_height: Option<u64>,
    ) -> CosmosMsg {
        self.client.execute(&ExecuteMsg::UpdateVotingParameters {
            voting_threshold,
            block_expiry,
            confirmation_height,
        })
    }

    pub fn poll(&self, poll_id: PollId) -> Result<PollResponse> {
        let msg = QueryMsg::Poll { poll_id };
        self.client
            .query(&msg)
            .change_context_lazy(|| Error::for_query(msg))
    }

    pub fn messages_status(&self, messages: Vec<Message>) -> Result<Vec<MessageStatus>> {
        match messages.as_slice() {
            [] => Ok(vec![]),
            _ => {
                let msg = QueryMsg::MessagesStatus(messages);
                self.client
                    .query(&msg)
                    .change_context_lazy(|| Error::for_query(msg))
            }
        }
    }

    pub fn verifier_set_status(&self, new_verifier_set: VerifierSet) -> Result<VerificationStatus> {
        let msg = QueryMsg::VerifierSetStatus(new_verifier_set);
        self.client
            .query(&msg)
            .change_context_lazy(|| Error::for_query(msg))
    }

    pub fn voting_parameters(&self) -> Result<VotingParameters> {
        let msg = QueryMsg::VotingParameters;
        self.client
            .query(&msg)
            .change_context_lazy(|| Error::for_query(msg))
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use assert_ok::assert_ok;
    use axelar_wasm_std::address::{validate_address, AddressFormat};
    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelar_wasm_std::{Threshold, VerificationStatus};
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env, MockQuerier};
    use cosmwasm_std::{
        from_json, Addr, Binary, DepsMut, QuerierResult, QuerierWrapper, SystemError, Uint128,
        Uint64, WasmQuery,
    };
    use multisig::verifier_set::VerifierSet;
    use router_api::{address, chain_name, cosmos_addr, CrossChainId, Message};

    use crate::contract::{instantiate, query};
    use crate::msg::{InstantiateMsg, MessageStatus, QueryMsg};
    use crate::Client;

    #[test]
    fn query_messages_status() {
        let (querier, _, addr) = setup();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

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
            source_address: address!("0x1234"),
            destination_address: address!("0x5678"),
            destination_chain: chain_name!("eth"),
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
            source_address: address!("0x4321"),
            destination_address: address!("0x8765"),
            destination_chain: chain_name!("eth"),
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
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

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
    fn query_voting_parameters() {
        let (querier, instantiate_msg, addr) = setup();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        let params = client.voting_parameters();
        assert_ok!(&params);
        let params = params.unwrap();
        assert_eq!(params.voting_threshold, instantiate_msg.voting_threshold);
        assert_eq!(params.block_expiry, instantiate_msg.block_expiry);
        assert_eq!(
            params.confirmation_height,
            instantiate_msg.confirmation_height
        );
    }

    #[test]
    fn query_verifier_set_returns_error_when_query_fails() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.verifier_set_status(VerifierSet {
            signers: BTreeMap::new(),
            threshold: Uint128::one(),
            created_at: 0,
        });

        assert!(res.is_err());
        goldie::assert!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_messages_status_returns_error_when_query_fails() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.messages_status(vec![Message {
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
            source_address: address!("0x1234"),
            destination_address: address!("0x5678"),
            destination_chain: chain_name!("eth"),
            payload_hash: [0; 32],
        }]);

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
    fn query_voting_parameters_returns_error_when_query_fails() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.voting_parameters();

        assert!(res.is_err());
        goldie::assert!(res.unwrap_err().to_string());
    }

    fn setup_queries_to_fail() -> (MockQuerier, Addr) {
        let addr = cosmos_addr!("voting-verifier");
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

    fn chain_codec_handler(msg: &Binary) -> QuerierResult {
        let msg = from_json::<chain_codec_api::msg::QueryMsg>(msg).unwrap();

        match msg {
            chain_codec_api::msg::QueryMsg::ValidateAddress { address } => {
                Ok(validate_address(&address, &AddressFormat::Eip55)
                    .map(|_| cosmwasm_std::to_json_binary(&cosmwasm_std::Empty {}).unwrap())
                    .into())
                .into()
            }
            _ => panic!("unexpected query: {:?}", msg),
        }
    }

    fn setup() -> (MockQuerier, InstantiateMsg, Addr) {
        let mut deps = mock_dependencies();
        deps.querier.update_wasm(|q| match q {
            WasmQuery::Smart { contract_addr, msg }
                if contract_addr == cosmos_addr!("chain-codec").as_str() =>
            {
                chain_codec_handler(msg)
            }
            _ => Err(SystemError::Unknown {}).into(),
        });
        let addr = cosmos_addr!("voting-verifier");
        let addr_clone = addr.clone();
        let instantiate_msg = instantiate_contract(deps.as_mut());

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart { contract_addr, msg } => {
                if contract_addr == addr.as_str() {
                    let msg = from_json::<QueryMsg>(msg).unwrap();
                    Ok(query(deps.as_ref(), mock_env(), msg).into()).into()
                } else if contract_addr == cosmos_addr!("chain-codec").as_str() {
                    chain_codec_handler(msg)
                } else {
                    Err(SystemError::Unknown {}).into()
                }
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        (querier, instantiate_msg, addr_clone)
    }

    fn instantiate_contract(deps: DepsMut) -> InstantiateMsg {
        let env = mock_env();
        let info = message_info(&cosmos_addr!("deployer"), &[]);

        let msg = InstantiateMsg {
            governance_address: cosmos_addr!("governance").to_string().try_into().unwrap(),
            service_registry_address: cosmos_addr!("service-registry")
                .to_string()
                .try_into()
                .unwrap(),
            service_name: "voting-verifier".try_into().unwrap(),
            source_gateway_address: "0x4F4495243837681061C4743b74B3eEdf548D56A5"
                .try_into()
                .unwrap(),
            voting_threshold: Threshold::try_from((Uint64::new(2), Uint64::new(3)))
                .unwrap()
                .try_into()
                .unwrap(),
            block_expiry: 100.try_into().unwrap(),
            confirmation_height: 10,
            source_chain: chain_name!("source-chain"),
            rewards_address: cosmos_addr!("rewards").to_string().try_into().unwrap(),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
            chain_codec_address: cosmos_addr!("chain-codec").to_string().try_into().unwrap(),
        };

        instantiate(deps, env, info.clone(), msg.clone()).unwrap();

        msg
    }
}
