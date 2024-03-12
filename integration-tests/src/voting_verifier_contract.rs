use crate::contract::Contract;
use axelar_wasm_std::nonempty;
use axelar_wasm_std::MajorityThreshold;
use connection_router_api::ChainName;
use cosmwasm_std::Addr;
use cw_multi_test::{App, ContractWrapper, Executor};

#[derive(Clone)]
pub struct VotingVerifierContract {
    pub contract_addr: Addr,
}

impl VotingVerifierContract {
    pub fn instantiate_contract(
        app: &mut App,
        service_registry_address: nonempty::String,
        service_name: nonempty::String,
        source_gateway_address: nonempty::String,
        voting_threshold: MajorityThreshold,
        source_chain: ChainName,
        rewards_address: Addr,
    ) -> Self {
        let code = ContractWrapper::new(
            voting_verifier::contract::execute,
            voting_verifier::contract::instantiate,
            voting_verifier::contract::query,
        );
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("anyone"),
                &voting_verifier::msg::InstantiateMsg {
                    service_registry_address,
                    service_name,
                    source_gateway_address,
                    voting_threshold,
                    block_expiry: 10,
                    confirmation_height: 5,
                    source_chain,
                    rewards_address: rewards_address.to_string(),
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
