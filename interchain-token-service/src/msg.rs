use std::collections::HashMap;

use axelarnet_gateway::AxelarExecutableMsg;
use cosmwasm_schema::{cw_serde, QueryResponses};
use msgs_derive::EnsurePermissions;
use router_api::{Address, ChainName, ChainNameRaw};

use crate::state::TokenBalance;
use crate::TokenId;

#[cw_serde]
pub struct InstantiateMsg {
    pub governance_address: String,
    pub admin_address: String,
    pub chain_name: ChainNameRaw,
    pub gateway_address: String,
    pub its_addresses: HashMap<ChainName, Address>,
}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    #[permission(Specific(gateway))]
    Execute(AxelarExecutableMsg),
    #[permission(Governance)]
    SetItsAddress { chain: ChainName, address: Address },
    #[permission(Elevated)]
    RemoveItsAddress { chain: ChainName },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(ItsAddressResponse)]
    SetItsAddress { chain: ChainName },
    #[returns(AllItsAddressesResponse)]
    AllItsAddresses {},
    #[returns(TokenBalanceResponse)]
    TokenBalance { chain: ChainName, token_id: TokenId },
}

#[cw_serde]
pub struct ItsAddressResponse {
    pub address: Option<Address>,
}

#[cw_serde]
pub struct AllItsAddressesResponse {
    pub addresses: HashMap<ChainName, Address>,
}

#[cw_serde]
pub struct TokenBalanceResponse {
    pub balance: Option<TokenBalance>,
}
