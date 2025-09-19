use chain_codec_evm::contract::{instantiate, query};
use cosmwasm_std::testing::MockApi;
use cosmwasm_std::{Addr, Empty, StdError, StdResult};
use cw_multi_test::{ContractWrapper, Executor};

use crate::contract::Contract;
use crate::protocol::Protocol;

#[derive(Clone)]
pub struct ChainCodecContract {
    pub contract_addr: Addr,
    pub code_id: u64,
}

impl ChainCodecContract {
    pub fn instantiate_contract(protocol: &mut Protocol, multisig_prover: Addr) -> Self {
        let code = ContractWrapper::new_with_empty(
            |_, _, _, _: Empty| StdResult::Err(StdError::generic_err("no execute endpoint")),
            instantiate,
            query,
        );

        let app = &mut protocol.app;
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                MockApi::default().addr_make("anyone"),
                &chain_codec_api::msg::InstantiateMsg {
                    multisig_prover: multisig_prover.to_string(),
                },
                &[],
                "coordinator",
                None,
            )
            .unwrap();

        ChainCodecContract {
            contract_addr,
            code_id,
        }
    }
}

impl Contract for ChainCodecContract {
    type QMsg = chain_codec_api::msg::QueryMsg;
    type ExMsg = Empty;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
