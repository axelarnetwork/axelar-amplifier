use aggregate_verifier::{
    contract::*,
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
};
use cosmwasm_std::Addr;
use cw_multi_test::{App, ContractWrapper, Executor};
use integration_tests::contract::Contract;

pub struct AggregateVerifierContract {
    pub contract_addr: Addr,
}

impl AggregateVerifierContract {
    pub fn instantiate_contract(app: &mut App, voting_verifier_address: Addr) -> Self {
        let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("gateway"),
                &InstantiateMsg {
                    verifier_address: voting_verifier_address.to_string(),
                },
                &[],
                "Contract",
                None,
            )
            .unwrap();

        AggregateVerifierContract { contract_addr }
    }
}

impl Contract for AggregateVerifierContract {
    type QMsg = QueryMsg;
    type ExMsg = ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
