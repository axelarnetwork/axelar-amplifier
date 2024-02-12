use crate::contract::Error;
use axelar_wasm_std::VerificationStatus;
use connection_router::state::CrossChainId;
use connection_router::Message;
use cosmwasm_std::{to_binary, Addr, QuerierWrapper, QueryRequest, WasmMsg, WasmQuery};
use error_stack::{Result, ResultExt};
use serde::de::DeserializeOwned;
use std::collections::HashMap;

pub struct Verifier<'a> {
    pub querier: QuerierWrapper<'a>,
    pub address: Addr,
}

impl Verifier<'_> {
    fn query<U: DeserializeOwned + 'static>(
        &self,
        msg: &aggregate_verifier::msg::QueryMsg,
    ) -> Result<U, Error> {
        self.querier
            .query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: self.address.to_string(),
                msg: to_binary(&msg).expect("msg should always be serializable"),
            }))
            .change_context(Error::QueryVerifier)
    }

    fn execute(&self, msg: &aggregate_verifier::msg::ExecuteMsg) -> WasmMsg {
        WasmMsg::Execute {
            contract_addr: self.address.to_string(),
            msg: to_binary(msg).expect("msg should always be serializable"),
            funds: vec![],
        }
    }

    pub(crate) fn messages_status(
        &self,
        msgs: Vec<Message>,
    ) -> Result<impl Iterator<Item = (Message, VerificationStatus)>, Error> {
        let response: Vec<(CrossChainId, VerificationStatus)> =
            self.query(&aggregate_verifier::msg::QueryMsg::GetMessagesStatus {
                messages: msgs.clone(),
            })?;

        let status_by_id = response.into_iter().collect::<HashMap<_, _>>();

        Ok(msgs.into_iter().map(move |msg| {
            let status = status_by_id
                .get(&msg.cc_id)
                .copied()
                .unwrap_or(VerificationStatus::None);
            (msg, status)
        }))
    }

    pub(crate) fn verify(&self, msgs: Vec<Message>) -> WasmMsg {
        self.execute(&aggregate_verifier::msg::ExecuteMsg::VerifyMessages { messages: msgs })
    }
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::VerificationStatus;
    use connection_router::state::CrossChainId;
    use cosmwasm_std::testing::MockQuerier;
    use std::str::FromStr;

    use super::*;

    #[test]
    fn verifier_returns_error_when_query_fails() {
        let querier = MockQuerier::default();
        let verifier = Verifier {
            address: Addr::unchecked("not a contract"),
            querier: QuerierWrapper::new(&querier),
        };

        let result = verifier.query::<Vec<(CrossChainId, VerificationStatus)>>(
            &aggregate_verifier::msg::QueryMsg::GetMessagesStatus { messages: vec![] },
        );

        assert!(matches!(
            result.unwrap_err().current_context(),
            Error::QueryVerifier
        ))
    }

    #[test]
    fn verifier_returns_error_on_return_type_mismatch() {
        let mut querier = MockQuerier::default();
        querier.update_wasm(|_| {
            Ok(to_binary(&CrossChainId::from_str("eth:0x1234").unwrap()).into()).into()
        });

        let verifier = Verifier {
            address: Addr::unchecked("not a contract"),
            querier: QuerierWrapper::new(&querier),
        };

        let result = verifier.query::<Vec<(CrossChainId, VerificationStatus)>>(
            &aggregate_verifier::msg::QueryMsg::GetMessagesStatus { messages: vec![] },
        );

        assert!(matches!(
            result.unwrap_err().current_context(),
            Error::QueryVerifier
        ))
    }
}
