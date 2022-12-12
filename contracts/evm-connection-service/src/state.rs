use std::collections::HashMap;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint64};
use cw_storage_plus::{Item, Map};
use service_interface::msg::ActionMessage;

#[cw_serde]
pub struct ServiceInfo {
    pub name: String,
    pub threshold: Uint64,
}

#[cw_serde]
pub struct ActionRequest {
    pub message: ActionMessage,
    pub votes: HashMap<bool, Uint64>,
    pub voters: HashMap<Addr, bool>,
    pub consensus_reached: bool,
    // Add timeout in block number
    // add block
}

impl ActionRequest {
    pub fn new(message: ActionMessage) -> Self {
        Self {
            message,
            votes: HashMap::new(),
            voters: HashMap::new(),
            consensus_reached: false,
        }
    }
}

pub const SERVICE_INFO: Item<ServiceInfo> = Item::new("service");
pub const ACTION_REQUESTS: Map<&[u8], ActionRequest> = Map::new("action_requests");
