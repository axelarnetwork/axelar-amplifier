use crate::error::ContractError;
use cosmwasm_std::{to_binary, Addr, QuerierWrapper, QueryRequest, WasmMsg, WasmQuery};
use error_stack::{Result, ResultExt};
use mockall::automock;
use serde::de::DeserializeOwned;

#[automock]
pub trait Verifier {
    fn query<U: DeserializeOwned + 'static>(
        &self,
        msg: aggregate_verifier::msg::QueryMsg,
    ) -> Result<U, ContractError>;

    fn address(&self) -> Addr;

    fn execute(&self, msg: &aggregate_verifier::msg::ExecuteMsg) -> Result<WasmMsg, ContractError> {
        execute(&self.address(), msg)
    }
}

pub fn execute(
    verifier_addr: &Addr,
    msg: &aggregate_verifier::msg::ExecuteMsg,
) -> Result<WasmMsg, ContractError> {
    Ok(WasmMsg::Execute {
        contract_addr: verifier_addr.to_string(),
        msg: to_binary(msg).change_context(ContractError::CreateVerifierExecuteMsg)?,
        funds: vec![],
    })
}

pub struct VerifierApi<'a> {
    pub address: Addr,
    pub querier: QuerierWrapper<'a>,
}

impl Verifier for VerifierApi<'_> {
    fn query<U: DeserializeOwned + 'static>(
        &self,
        msg: aggregate_verifier::msg::QueryMsg,
    ) -> Result<U, ContractError> {
        self.querier
            .query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: self.address.to_string(),
                msg: to_binary(&msg).change_context(ContractError::QueryVerifier)?,
            }))
            .change_context(ContractError::QueryVerifier)
    }

    fn address(&self) -> Addr {
        self.address.clone()
    }
}
