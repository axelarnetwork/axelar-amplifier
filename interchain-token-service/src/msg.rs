use std::collections::HashMap;

use axelarnet_gateway::AxelarExecutableMsg;
use cosmwasm_schema::{cw_serde, QueryResponses};
use msgs_derive::EnsurePermissions;
use router_api::{Address, ChainName};

#[cw_serde]
pub struct InstantiateMsg {
    pub governance_address: String,
    pub admin_address: String,
    /// The address of the axelarnet-gateway contract on Amplifier
    pub axelarnet_gateway_address: String,
    /// Addresses of the ITS contracts on existing chains
    pub its_addresses: HashMap<ChainName, Address>,
}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    /// Execute a cross-chain message received by the axelarnet-gateway from another chain
    #[permission(Specific(gateway))]
    Execute(AxelarExecutableMsg),
    /// Set the ITS contract address of another chain. Each chain's ITS contract has to be whitelisted before
    /// ITS Hub can send cross-chain messages to it, or receive messages from it.
    /// If an ITS address is already set for the chain, it will be overwritten.
    /// This allows easier management of ITS contracts without the need for migration.
    #[permission(Governance)]
    SetItsAddress { chain: ChainName, address: Address },
    /// Remove the configured ITS contract address for the given chain.
    /// The admin is allowed to remove the ITS address of a chain for emergencies.
    #[permission(Elevated)]
    RemoveItsAddress { chain: ChainName },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// Query the ITS contract address of a chain
    #[returns(Option<Address>)]
    ItsAddress { chain: ChainName },
    /// Query all configured ITS contract addresses
    #[returns(HashMap<ChainName, Address>)]
    AllItsAddresses,
}
