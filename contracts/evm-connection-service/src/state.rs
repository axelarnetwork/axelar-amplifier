use std::collections::HashMap;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint64};
use cw_storage_plus::Map;
use service_interface::msg::ActionMessage;

#[cw_serde]
pub struct ActionRequest {
    pub message: ActionMessage,
    pub votes: HashMap<bool, Uint64>,
    pub voters: HashMap<Addr, bool>,
}

impl ActionRequest {
    pub fn new(message: ActionMessage) -> Self {
        Self {
            message,
            votes: HashMap::new(),
            voters: HashMap::new(),
        }
    }
}

pub const ACTION_REQUESTS: Map<&[u8], ActionRequest> = Map::new("action_requests");
