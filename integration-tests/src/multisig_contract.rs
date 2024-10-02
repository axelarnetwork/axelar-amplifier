use axelar_wasm_std::nonempty;
use cosmwasm_std::Addr;
use cw_multi_test::{ContractWrapper, Executor};
use multisig::contract::{execute, instantiate, query};

use crate::contract::Contract;
use crate::protocol::AxelarApp;

#[derive(Clone)]
pub struct MultisigContract {
    pub contract_addr: Addr,
}

impl MultisigContract {
    pub fn instantiate_contract(
        app: &mut AxelarApp,
        governance: Addr,
        admin: Addr,
        rewards_address: Addr,
        block_expiry: nonempty::Uint64,
    ) -> Self {
        let code = ContractWrapper::new_with_empty(execute, instantiate, query);
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("anyone"),
                &multisig::msg::InstantiateMsg {
                    rewards_address: rewards_address.to_string(),
                    governance_address: governance.to_string(),
                    admin_address: admin.to_string(),
                    block_expiry,
                },
                &[],
                "multisig",
                None,
            )
            .unwrap();

        MultisigContract { contract_addr }
    }
}

impl Contract for MultisigContract {
    type QMsg = multisig::msg::QueryMsg;
    type ExMsg = multisig::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
