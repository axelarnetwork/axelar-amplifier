use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Uint128};
use service_interface::msg::ActionMessage;

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    RouteMessage {
        message: ActionMessage,
    },
    UpdateRoute {
        chain_id: Uint128,
        destination_contract: Addr,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {}
