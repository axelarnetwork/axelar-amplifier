use std::collections::HashMap;

use axelarnet_gateway::AxelarExecutableMsg;
use cosmwasm_schema::{cw_serde, QueryResponses};
use msgs_derive::EnsurePermissions;
use router_api::{Address, ChainNameRaw};

#[cw_serde]
pub struct InstantiateMsg {
    pub governance_address: String,
    pub admin_address: String,
    /// The address of the axelarnet-gateway contract on Amplifier
    pub axelarnet_gateway_address: String,
    /// Addresses of the ITS edge contracts on connected chains
    pub its_addresses: HashMap<ChainNameRaw, Address>,
}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    /// Execute a cross-chain message received by the axelarnet-gateway from another chain
    #[permission(Specific(gateway))]
    Execute(AxelarExecutableMsg),
    /// Register the ITS contract address of another chain. Each chain's ITS contract has to be whitelisted before
    /// ITS Hub can send cross-chain messages to it, or receive messages from it.
    /// If an ITS address is already set for the chain, an error is returned.
    #[permission(Governance)]
    RegisterItsAddress {
        chain: ChainNameRaw,
        address: Address,
    },
    /// Deregister the ITS contract address for the given chain.
    /// The admin is allowed to remove the ITS address of a chain for emergencies.
    #[permission(Elevated)]
    DeregisterItsAddress { chain: ChainNameRaw },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// Query the ITS contract address of a chain
    #[returns(Option<Address>)]
    ItsAddress { chain: ChainNameRaw },
    /// Query all configured ITS contract addresses
    #[returns(HashMap<ChainNameRaw, Address>)]
    AllItsAddresses,
}
