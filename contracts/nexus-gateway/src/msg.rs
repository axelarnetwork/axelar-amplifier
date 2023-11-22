use cosmwasm_schema::{cw_serde, QueryResponses};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::nexus;

#[cw_serde]
pub struct InstantiateMsg {
    pub nexus: String,
    pub router: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(untagged)]
pub enum Message {
    RouterMessage(connection_router::Message),
    NexusMessage(nexus::Message),
}

impl From<Message> for connection_router::Message {
    fn from(msg: Message) -> Self {
        match msg {
            Message::RouterMessage(msg) => msg,
            Message::NexusMessage(msg) => msg.into(),
        }
    }
}

impl From<Message> for nexus::Message {
    fn from(msg: Message) -> Self {
        match msg {
            Message::RouterMessage(msg) => msg.into(),
            Message::NexusMessage(msg) => msg,
        }
    }
}

#[cw_serde]
pub enum ExecuteMsg {
    RouteMessages(Vec<Message>),
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {}
