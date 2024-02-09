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

#[cfg(test)]
mod tests {
    use axelar_wasm_std::VerificationStatus;
    use connection_router::state::CrossChainId;
    use cosmwasm_std::testing::mock_dependencies;

    use super::*;

    #[test]
    fn query_returns_error() {
        let deps = mock_dependencies();

        let verifier = Verifier {
            address: Addr::unchecked("not a contract"),
            querier: VerifierApi {
                querier: deps.as_ref().querier,
            },
        };

        let result = verifier.query::<Vec<(CrossChainId, VerificationStatus)>>(
            &aggregate_verifier::msg::QueryMsg::GetMessagesStatus { messages: vec![] },
        );

        assert_eq!(
            result.unwrap_err().current_context(),
            &ContractError::QueryVerifier
        )
    }
}
