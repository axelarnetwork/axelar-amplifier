//! A helper contract for testing that implements the [`signature_verifier_api::msg`] interface and
//! always fails.

use cosmwasm_std::{
    Addr, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response, StdError, StdResult,
};
use cw_multi_test::{ContractWrapper, Executor};
use router_api::cosmos_addr;
use signature_verifier_api::msg::{ExecuteMsg, QueryMsg};

use crate::contract::Contract;
use crate::protocol::AxelarApp;

pub fn query(
    _deps: Deps,
    _env: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::error::ContractError> {
    match msg {
        QueryMsg::VerifySignature { .. } => Ok(cosmwasm_std::to_json_binary(&false)?),
    }
}

pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    match msg {
        ExecuteMsg::VerifySignature { .. } => Err(StdError::generic_err(
            "signature verifier is having a bad day",
        ))?,
    }
}

#[derive(Clone)]
pub struct FailingSigVerifier {
    pub contract_addr: Addr,
}

impl FailingSigVerifier {
    pub fn instantiate_contract(app: &mut AxelarApp) -> Self {
        let code = ContractWrapper::new_with_empty(
            execute,
            |_, _, _, _: Empty| StdResult::Ok(Response::new()),
            query,
        );
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                cosmos_addr!("anyone"),
                &Empty {},
                &[],
                "failing_signature_verifier",
                None,
            )
            .unwrap();

        FailingSigVerifier { contract_addr }
    }
}

impl Contract for FailingSigVerifier {
    type QMsg = signature_verifier_api::msg::QueryMsg;
    type ExMsg = signature_verifier_api::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
