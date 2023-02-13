use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Decimal, Uint128, Uint256, Uint64};

#[cw_serde]
pub struct InstantiateMsg {
    pub service_registry: Addr,
    pub service_name: String,
    pub source_chain_name: String,
    pub gateway_address: Addr,
    pub confirmation_height: Uint64,
    pub min_num_workers: Uint64,
    pub max_num_workers: Option<Uint64>,
    pub min_worker_bond: Uint128,
    pub unbonding_period: Uint128,
    pub description: String,
    pub voting_threshold: Decimal,
    pub min_voter_count: Uint64,
    pub reward_pool: Addr,
    pub voting_period: Uint64,
    pub voting_grace_period: Uint64,
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
}

#[cw_serde]
pub enum ActionResponse {
    ConfirmGatewayTxs {
        poll_id: Uint64,
        calls_hash: [u8; 32],
    },
}
