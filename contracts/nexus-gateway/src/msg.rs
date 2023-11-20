use cosmwasm_schema::cw_serde;
use error_stack::{Report, Result};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{error::ContractError, nexus};

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

impl TryFrom<Message> for nexus::Message {
    type Error = Report<ContractError>;

    fn try_from(msg: Message) -> Result<Self, ContractError> {
        match msg {
            Message::RouterMessage(msg) => msg.try_into(),
            Message::NexusMessage(msg) => Ok(msg),
        }
    }
}

#[cw_serde]
pub enum ExecuteMsg {
    RouteMessages(Vec<Message>),
}
