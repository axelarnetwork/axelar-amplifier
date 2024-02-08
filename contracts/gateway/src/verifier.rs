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

    fn execute(&self, msg: &aggregate_verifier::msg::ExecuteMsg) -> Result<WasmMsg, ContractError>;
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

    fn execute(&self, msg: &aggregate_verifier::msg::ExecuteMsg) -> Result<WasmMsg, ContractError> {
        Ok(WasmMsg::Execute {
            contract_addr: self.address.to_string(),
            msg: to_binary(&msg).change_context(ContractError::CreateVerifierExecuteMsg)?,
            funds: vec![],
        })
    }
}
