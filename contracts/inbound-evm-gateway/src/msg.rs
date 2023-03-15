use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cosmwasm_std::{Uint128, Uint256, Uint64};

use crate::state::{InboundSettings, ServiceInfo};

use auth_vote::AuthVoting;
pub use service_interface::msg::ExecuteMsg;
pub use service_interface::msg::QueryMsg;

#[cw_serde]
pub struct InstantiateMsg {
    // TODO: rename inbound/outbound variables
    pub service_info: ServiceInfo,
    pub registration_parameters: RegistrationParameters,
    pub inbound_settings: InboundSettings,
    pub auth_module: AuthVoting,
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
    ConfirmGatewayTxs {
        from_nonce: Uint256,
        to_nonce: Uint256,
    },
}

#[cw_serde]
pub enum ActionResponse {
    ConfirmGatewayTxs {
        poll_id: Uint64,
        calls_hash: [u8; 32],
    },
}

#[cw_serde]
pub enum AdminOperation {
    UpdateWorkersVotingPower { workers: Vec<WorkerVotingPower> },
}

#[cw_serde]
pub struct WorkerVotingPower {
    pub worker: Addr,
    pub voting_power: Uint256,
}
