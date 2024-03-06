use crate::{source_chain, POLL_BLOCK_EXPIRY};
use axelar_wasm_std::{nonempty, Threshold};
use cosmwasm_std::Addr;
use cw_multi_test::{App, ContractWrapper, Executor};
use integration_tests::contract::Contract;
use voting_verifier::{
    contract::*,
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
};

pub struct VotingVerifierContract {
    pub contract_addr: Addr,
}

impl VotingVerifierContract {
    pub fn instantiate_contract(
        app: &mut App,
        service_registry_address: nonempty::String,
        rewards_address: String,
    ) -> Self {
        let code = ContractWrapper::new(execute, instantiate, query);
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("sender"),
                &InstantiateMsg {
                    service_registry_address,
                    service_name: "service_name".parse().unwrap(),
                    voting_threshold: Threshold::try_from((2u64, 3u64))
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    block_expiry: POLL_BLOCK_EXPIRY,
                    confirmation_height: 100,
                    source_gateway_address: "gateway_address".parse().unwrap(),
                    source_chain: source_chain(),
                    rewards_address,
                },
                &[],
                "voting-verifier",
                None,
            )
            .unwrap();

        VotingVerifierContract { contract_addr }
    }
}

impl Contract for VotingVerifierContract {
    type QMsg = QueryMsg;
    type ExMsg = ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
