use axelarnet_gateway::AxelarExecutableMsg;
use cosmwasm_schema::{cw_serde, QueryResponses};
use msgs_derive::EnsurePermissions;
use router_api::{Address, ChainName};

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    #[permission(Any)]
    SendMessage {
        destination_chain: ChainName,
        destination_address: Address,
        message: String,
    },
    #[permission(Specific(gateway))]
    Execute(AxelarExecutableMsg),
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(String)]
    LastMessage {},
}
