use std::collections::HashMap;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Decimal};
use cosmwasm_std::{Binary, Uint128, Uint64};

use crate::state::{OutboundSettings, ServiceInfo};

use auth_multisig::AuthMultisig;
pub use service_interface::msg::ExecuteMsg;
pub use service_interface::msg::QueryMsg;

#[cw_serde]
pub struct InstantiateMsg {
    // TODO: rename inbound/outbound variables
    pub service_info: ServiceInfo,
    pub registration_parameters: RegistrationParameters,
    pub outbound_settings: OutboundSettings,
    pub auth_module: AuthMultisig,
}

#[cw_serde]
pub struct RegistrationParameters {
    pub description: String,
    pub min_num_workers: Uint64,
    pub max_num_workers: Option<Uint64>,
    pub min_worker_bond: Uint128,
    pub unbonding_period: Uint128,
}

#[cw_serde]
pub enum ActionMessage {
    SignCommands {},
}

#[cw_serde]
pub enum ActionResponse {
    SubmitSignature {
        signing_session_id: Uint64,
        signature: Binary,
    },
}

#[cw_serde]
pub enum AdminOperation {
    SetPubKeys {
        signing_treshold: Decimal,
        pub_keys: HashMap<Addr, Binary>,
    },
}
