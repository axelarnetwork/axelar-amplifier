use std::collections::HashMap;

use axelar_wasm_std::nonempty;
use axelarnet_gateway::AxelarExecutableMsg;
use cosmwasm_schema::{cw_serde, QueryResponses};
use msgs_derive::EnsurePermissions;
use router_api::{Address, ChainNameRaw};

use crate::state::{TokenConfig, TokenInstance};
use crate::TokenId;

// Pagination limit
const DEFAULT_LIMIT: u32 = 30;

const fn default_pagination_limit() -> u32 {
    DEFAULT_LIMIT
}

#[cw_serde]
pub struct InstantiateMsg {
    pub governance_address: String,
    pub admin_address: String,
    /// The address of the axelarnet-gateway contract on Amplifier
    pub axelarnet_gateway_address: String,
}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    /// Execute a cross-chain message received by the axelarnet-gateway from another chain
    #[permission(Specific(gateway))]
    Execute(AxelarExecutableMsg),

    /// For each chain, register the ITS contract and set config parameters.
    /// Each chain's ITS contract has to be whitelisted before
    /// ITS Hub can send cross-chain messages to it, or receive messages from it.
    /// If any chain is already registered, an error is returned.
    #[permission(Governance)]
    RegisterChains { chains: Vec<ChainConfig> },

    /// For each chain, update the ITS contract and config parameters.
    /// If any chain has not been registered, returns an error
    #[permission(Governance)]
    UpdateChains { chains: Vec<ChainConfig> },

    /// Freeze execution of ITS messages for a particular chain
    #[permission(Elevated)]
    FreezeChain { chain: ChainNameRaw },

    /// Unfreeze execution of ITS messages for a particular chain
    #[permission(Elevated)]
    UnfreezeChain { chain: ChainNameRaw },

    #[permission(Elevated)]
    DisableExecution,

    #[permission(Elevated)]
    EnableExecution,
}

#[cw_serde]
pub enum ChainStatusFilter {
    Frozen,
    Active,
}

#[cw_serde]
pub struct ChainFilter {
    pub status: Option<ChainStatusFilter>,
}

#[cw_serde]
pub struct ChainConfig {
    pub chain: ChainNameRaw,
    pub its_edge_contract: Address,
    pub truncation: TruncationConfig,
}

#[cw_serde]
pub struct TruncationConfig {
    pub max_uint: nonempty::Uint256, // The maximum uint value that is supported by the chain's token standard
    pub max_decimals_when_truncating: u8, // The maximum number of decimals that is preserved when deploying from a chain with a larger max_uint
}

#[cw_serde]
pub struct ChainConfigResponse {
    pub chain: ChainNameRaw,
    pub its_edge_contract: Address,
    pub truncation: TruncationConfig,
    pub frozen: bool,
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// Query the configuration registered for a chain
    #[returns(Option<ChainConfigResponse>)]
    ItsChain { chain: ChainNameRaw },

    /// Query all registered ITS contract addresses
    #[returns(HashMap<ChainNameRaw, Address>)]
    AllItsContracts,

    /// Query all chain configs with optional frozen filter
    // The list is paginated by:
    // - start_after: the chain name to start after, which the next page of results should start.
    // - limit: limit the number of chains returned, default is u32::MAX.
    #[returns(Vec<ChainConfigResponse>)]
    ItsChains {
        filter: Option<ChainFilter>,
        start_after: Option<ChainNameRaw>,
        #[serde(default = "default_pagination_limit")]
        limit: u32,
    },

    /// Query a token instance on a specific chain
    #[returns(Option<TokenInstance>)]
    TokenInstance {
        chain: ChainNameRaw,
        token_id: TokenId,
    },

    /// Query the configuration parameters for a token
    #[returns(Option<TokenConfig>)]
    TokenConfig { token_id: TokenId },

    /// Query the state of contract (enabled/disabled)
    #[returns(bool)]
    IsEnabled,
}
