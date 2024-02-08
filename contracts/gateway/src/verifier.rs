use crate::error::ContractError;
use cosmwasm_std::{to_binary, Addr, QuerierWrapper, QueryRequest, WasmMsg, WasmQuery};
use error_stack::{Result, ResultExt};
use mockall::automock;
use serde::de::DeserializeOwned;

#[automock]
pub trait VerifyQuery {
    fn query<U: DeserializeOwned + 'static>(
        &self,
        verifier_addr: &Addr,
        msg: aggregate_verifier::msg::QueryMsg,
    ) -> Result<U, ContractError>;
}

pub struct VerifierApi<'a> {
    pub querier: QuerierWrapper<'a>,
}

impl VerifyQuery for VerifierApi<'_> {
    fn query<U: DeserializeOwned + 'static>(
        &self,
        verifier_addr: &Addr,
        msg: aggregate_verifier::msg::QueryMsg,
    ) -> Result<U, ContractError> {
        self.querier
            .query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: verifier_addr.to_string(),
                msg: to_binary(&msg).change_context(ContractError::QueryVerifier)?,
            }))
            .change_context(ContractError::QueryVerifier)
    }
}

pub struct Verifier<V> {
    pub querier: V,
    pub address: Addr,
}

impl<V> Verifier<V>
where
    V: VerifyQuery,
{
    pub fn query<U: DeserializeOwned + 'static>(
        &self,
        msg: &aggregate_verifier::msg::QueryMsg,
    ) -> Result<U, ContractError> {
        self.querier.query(&self.address, msg.clone())
    }

    pub fn execute(
        &self,
        msg: &aggregate_verifier::msg::ExecuteMsg,
    ) -> Result<WasmMsg, ContractError> {
        Ok(WasmMsg::Execute {
            contract_addr: self.address.to_string(),
            msg: to_binary(msg).change_context(ContractError::CreateVerifierExecuteMsg)?,
            funds: vec![],
        })
    }
}
