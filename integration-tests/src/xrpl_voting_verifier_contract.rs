use axelar_wasm_std::voting::{PollId, Vote};
use axelar_wasm_std::MajorityThreshold;
use cosmwasm_std::Addr;
use cw_multi_test::{ContractWrapper, Executor};
use router_api::ChainName;
use xrpl_types::types::XRPLAccountId;
use xrpl_voting_verifier::contract::{execute, instantiate, query};

use crate::contract::Contract;
use crate::protocol::Protocol;
use crate::voting_verifier_contract::VotingContract;

#[derive(Clone)]
pub struct XRPLVotingVerifierContract {
    pub contract_addr: Addr,
}

impl XRPLVotingVerifierContract {
    pub fn instantiate_contract(
        protocol: &mut Protocol,
        source_gateway_address: XRPLAccountId,
        voting_threshold: MajorityThreshold,
        source_chain: ChainName,
    ) -> Self {
        let code = ContractWrapper::new_with_empty(execute, instantiate, query);
        let app = &mut protocol.app;
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("anyone"),
                &xrpl_voting_verifier::msg::InstantiateMsg {
                    admin_address: protocol
                        .router_admin_address
                        .to_string()
                        .try_into()
                        .unwrap(),
                    governance_address: protocol.governance_address.to_string().try_into().unwrap(),
                    service_registry_address: protocol
                        .service_registry
                        .contract_addr
                        .to_string()
                        .try_into()
                        .unwrap(),
                    service_name: protocol.service_name.clone(),
                    source_gateway_address,
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
                },
                &[],
                "xrpl_voting_verifier",
                None,
            )
            .unwrap();

        XRPLVotingVerifierContract { contract_addr }
    }
}

impl Contract for XRPLVotingVerifierContract {
    type QMsg = xrpl_voting_verifier::msg::QueryMsg;
    type ExMsg = xrpl_voting_verifier::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}

impl VotingContract for XRPLVotingVerifierContract {
    fn construct_vote_message(poll_id: PollId, messages_len: usize, vote: Vote) -> Self::ExMsg {
        xrpl_voting_verifier::msg::ExecuteMsg::Vote {
            poll_id,
            votes: vec![vote; messages_len],
        }
    }

    fn construct_end_poll_message(poll_id: PollId) -> Self::ExMsg {
        xrpl_voting_verifier::msg::ExecuteMsg::EndPoll { poll_id }
    }
}
