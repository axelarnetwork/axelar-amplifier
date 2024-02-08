use cosmwasm_std::Addr;
use cw_multi_test::{App, ContractWrapper, Executor};
use integration_tests::contract::Contract;
use service_registry::{
    contract::{execute, instantiate, query},
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
};

pub struct ServiceRegistryContract {
    pub contract_addr: Addr,
}

impl ServiceRegistryContract {
    pub fn instantiate_contract(app: &mut App, governance: Addr) -> Self {
        let code = ContractWrapper::new(execute, instantiate, query);
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("anyone"),
                &InstantiateMsg {
                    governance_account: governance.clone().into(),
                },
                &[],
                "service_registry",
                None,
            )
            .unwrap();

        ServiceRegistryContract { contract_addr }
    }
}

impl Contract for ServiceRegistryContract {
    type QMsg = QueryMsg;
    type ExMsg = ExecuteMsg;
    type Err = axelar_wasm_std::ContractError;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
