use std::collections::HashMap;

use axelarnet_gateway::AxelarExecutableMsg;
use cosmwasm_schema::{cw_serde, QueryResponses};
use msgs_derive::EnsurePermissions;
use router_api::{Address, ChainName, ChainNameRaw};

use crate::state::TokenBalance;
use crate::TokenId;

#[cw_serde]
pub struct InstantiateMsg {
    pub chain_name: ChainNameRaw,
    pub gateway_address: String,
    pub trusted_addresses: Option<HashMap<ChainName, Address>>,
}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    #[permission(Specific(gateway))]
    Execute(AxelarExecutableMsg),
    #[permission(Governance)]
    SetTrustedAddress { chain: ChainName, address: Address },
    #[permission(Elevated)]
    RemoveTrustedAddress { chain: ChainName },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(TrustedAddressResponse)]
    TrustedAddress { chain: ChainName },
    #[returns(AllTrustedAddressesResponse)]
    AllTrustedAddresses {},
    #[returns(TokenBalanceResponse)]
    TokenBalance { chain: ChainName, token_id: TokenId },
}

#[cw_serde]
pub struct TrustedAddressResponse {
    pub address: Option<Address>,
}

#[cw_serde]
pub struct AllTrustedAddressesResponse {
    pub addresses: HashMap<ChainName, Address>,
}

#[cw_serde]
pub struct TokenBalanceResponse {
    pub balance: Option<TokenBalance>,
}
