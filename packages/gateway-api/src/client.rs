use axelar_wasm_std::vec::VecExt;
use cosmwasm_std::WasmMsg;
use error_stack::ResultExt;
use router_api::{CrossChainId, Message};

use crate::msg::{ExecuteMsg, QueryMsg};

type Result<T> = error_stack::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to query gateway for outgoing messages. message ids: {0:?}")]
    QueryOutgoingMessages(Vec<CrossChainId>),
}

impl<'a> From<client::Client<'a, ExecuteMsg, QueryMsg>> for Client<'a> {
    fn from(client: client::Client<'a, ExecuteMsg, QueryMsg>) -> Self {
        Client { client }
    }
}

pub struct Client<'a> {
    client: client::Client<'a, ExecuteMsg, QueryMsg>,
}

impl<'a> Client<'a> {
    pub fn outgoing_messages(&self, message_ids: Vec<CrossChainId>) -> Result<Vec<Message>> {
        self.client
            .query(&QueryMsg::OutgoingMessages(message_ids.clone()))
            .change_context_lazy(|| Error::QueryOutgoingMessages(message_ids))
    }

    pub fn verify_messages(&self, messages: Vec<Message>) -> Option<WasmMsg> {
        messages
            .to_none_if_empty()
            .map(|messages| self.client.execute(&ExecuteMsg::VerifyMessages(messages)))
    }

    pub fn route_messages(&self, messages: Vec<Message>) -> Option<WasmMsg> {
        messages
            .to_none_if_empty()
            .map(|messages| self.client.execute(&ExecuteMsg::RouteMessages(messages)))
    }
}
