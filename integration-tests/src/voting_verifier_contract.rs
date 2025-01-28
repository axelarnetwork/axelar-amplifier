use axelar_wasm_std::voting::{Vote, PollId};
use axelar_wasm_std::MajorityThreshold;
use cosmwasm_std::testing::MockApi;
use cosmwasm_std::Addr;
use cw_multi_test::{ContractWrapper, Executor};
use router_api::ChainName;
use voting_verifier::contract::{execute, instantiate, query};

use crate::contract::Contract;
use crate::protocol::Protocol;

#[derive(Clone)]
pub struct VotingVerifierContract {
    pub contract_addr: Addr,
}

impl VotingVerifierContract {
    pub fn instantiate_contract(
        protocol: &mut Protocol,
        voting_threshold: MajorityThreshold,
        source_chain: ChainName,
    ) -> Self {
        let code = ContractWrapper::new_with_empty(execute, instantiate, query);
        let app = &mut protocol.app;
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                MockApi::default().addr_make("anyone"),
                &voting_verifier::msg::InstantiateMsg {
                    governance_address: protocol.governance_address.to_string().try_into().unwrap(),
                    service_registry_address: protocol
                        .service_registry
                        .contract_addr
                        .to_string()
                        .try_into()
                        .unwrap(),
                    service_name: protocol.service_name.clone(),
                    source_gateway_address: "0x4F4495243837681061C4743b74B3eEdf548D56A5"
                        .try_into()
                        .unwrap(),
                    voting_threshold,
                    block_expiry: 10.try_into().unwrap(),
                    confirmation_height: 5,
                    source_chain,
                    rewards_address: protocol
                        .rewards
                        .contract_addr
                        .to_string()
                        .try_into()
                        .unwrap(),
                    msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
                    address_format: axelar_wasm_std::address::AddressFormat::Eip55,
                },
                &[],
                "voting_verifier",
                None,
            )
            .unwrap();

        VotingVerifierContract { contract_addr }
    }
}

impl Contract for VotingVerifierContract {
    type QMsg = voting_verifier::msg::QueryMsg;
    type ExMsg = voting_verifier::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}

pub trait VotingContract: Contract {
    fn construct_vote_message(poll_id: PollId, messages_len: usize, vote: Vote) -> Self::ExMsg;
    fn construct_end_poll_message(poll_id: PollId) -> Self::ExMsg;
}

impl VotingContract for VotingVerifierContract {
    fn construct_vote_message(poll_id: PollId, messages_len: usize, vote: Vote) -> Self::ExMsg {
        voting_verifier::msg::ExecuteMsg::Vote {
            poll_id,
            votes: vec![vote; messages_len],
        }
    }

    fn construct_end_poll_message(poll_id: PollId) -> Self::ExMsg {
        voting_verifier::msg::ExecuteMsg::EndPoll { poll_id }
    }
}
