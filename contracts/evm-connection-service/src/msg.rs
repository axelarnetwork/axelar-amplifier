use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Binary, Uint128, Uint256, Uint64};

use crate::state::{InboundSettings, OutboundSettings, ServiceInfo};

#[cw_serde]
pub struct InstantiateMsg {
    // TODO: rename inbound/outbound variables
    pub service_info: ServiceInfo,
    pub registration_parameters: RegistrationParameters,
    pub inbound_settings: InboundSettings,
    pub outbound_settings: OutboundSettings,
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
pub enum ExecuteMsg {}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {}

#[cw_serde]
pub enum ActionMessage {
    ConfirmGatewayTxs {
        from_nonce: Uint256,
        to_nonce: Uint256,
    },
    RequestWorkerSignatures {},
}

#[cw_serde]
pub enum ActionResponse {
    ConfirmGatewayTxs {
        poll_id: Uint64,
        calls_hash: [u8; 32],
    },
    SubmitSignature {
        signing_session_id: Uint64,
        signature: Binary,
    },
}
