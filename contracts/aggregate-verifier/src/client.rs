use axelar_wasm_std::utils::TryMapExt;
use axelar_wasm_std::{FnExt, VerificationStatus};
use connection_router_api::{CrossChainId, Message};
use cosmwasm_std::{to_json_binary, Addr, QuerierWrapper, QueryRequest, WasmMsg, WasmQuery};
use error_stack::{Result, ResultExt};
use serde::de::DeserializeOwned;
use std::collections::HashMap;

pub struct Verifier<'a> {
    pub querier: QuerierWrapper<'a>,
    pub address: Addr,
}

impl Verifier<'_> {
    fn execute(&self, msg: &crate::msg::ExecuteMsg) -> WasmMsg {
        WasmMsg::Execute {
            contract_addr: self.address.to_string(),
            msg: to_json_binary(msg).expect("msg should always be serializable"),
            funds: vec![],
        }
    }

    fn query<U: DeserializeOwned + 'static>(&self, msg: &crate::msg::QueryMsg) -> Result<U, Error> {
        self.querier
            .query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: self.address.to_string(),
                msg: to_json_binary(&msg).expect("msg should always be serializable"),
            }))
            .change_context(Error::QueryVerifier)
    }

    pub fn verify(&self, msgs: Vec<Message>) -> Option<WasmMsg> {
        ignore_empty(msgs)
            .map(|msgs| self.execute(&crate::msg::ExecuteMsg::VerifyMessages { messages: msgs }))
    }

    pub fn messages_with_status(
        &self,
        msgs: Vec<Message>,
    ) -> Result<impl Iterator<Item = (Message, VerificationStatus)>, Error> {
        ignore_empty(msgs.clone())
            .try_map(|msgs| self.query_message_status(msgs))?
            .map(|status_by_id| ids_to_msgs(status_by_id, msgs))
            .into_iter()
            .flatten()
            .then(Ok)
    }

    fn query_message_status(
        &self,
        msgs: Vec<Message>,
    ) -> Result<HashMap<CrossChainId, VerificationStatus>, Error> {
        self.query::<Vec<(CrossChainId, VerificationStatus)>>(
            &crate::msg::QueryMsg::GetMessagesStatus { messages: msgs },
        )?
        .into_iter()
        .collect::<HashMap<_, _>>()
        .then(Ok)
    }
}

// TODO: unify across contract clients
fn ignore_empty(msgs: Vec<Message>) -> Option<Vec<Message>> {
    if msgs.is_empty() {
        None
    } else {
        Some(msgs)
    }
}

fn ids_to_msgs(
    status_by_id: HashMap<CrossChainId, VerificationStatus>,
    msgs: Vec<Message>,
) -> impl Iterator<Item = (Message, VerificationStatus)> {
    msgs.into_iter().map(move |msg| {
        let status = status_by_id
            .get(&msg.cc_id)
            .copied()
            .unwrap_or(VerificationStatus::None);
        (msg, status)
    })
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("could not query the verifier contract")]
    QueryVerifier,
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::VerificationStatus;
    use connection_router_api::{CrossChainId, CHAIN_NAME_DELIMITER};
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
            &crate::msg::QueryMsg::GetMessagesStatus { messages: vec![] },
        );

        assert!(matches!(
            result.unwrap_err().current_context(),
            Error::QueryVerifier
        ))
    }

    // due to contract updates or misconfigured verifier contract address the verifier might respond,
    // but deliver an unexpected data type. This tests that the client returns an error in such cases.
    #[test]
    fn verifier_returns_error_on_return_type_mismatch() {
        let mut querier = MockQuerier::default();
        querier.update_wasm(|_| {
            Ok(to_json_binary(
                &CrossChainId::from_str(format!("eth{}0x1234", CHAIN_NAME_DELIMITER).as_str())
                    .unwrap(),
            )
            .into())
            .into()
        });

        let verifier = Verifier {
            address: Addr::unchecked("not a contract"),
            querier: QuerierWrapper::new(&querier),
        };

        let result = verifier.query::<Vec<(CrossChainId, VerificationStatus)>>(
            &crate::msg::QueryMsg::GetMessagesStatus { messages: vec![] },
        );

        assert!(matches!(
            result.unwrap_err().current_context(),
            Error::QueryVerifier
        ))
    }
}
