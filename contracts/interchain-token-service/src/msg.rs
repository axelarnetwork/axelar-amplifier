use std::collections::HashMap;

use axelar_wasm_std::nonempty;
use axelarnet_gateway::AxelarExecutableMsg;
use cosmwasm_schema::{cw_serde, QueryResponses};
use msgs_derive::EnsurePermissions;
use router_api::{Address, ChainNameRaw};

use crate::state::{TokenConfig, TokenInstance};
use crate::TokenId;

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
    /// If an ITS contract is already set for the chain, an error is returned.
    #[permission(Governance)]
    RegisterChains { chains: Vec<ChainConfig> },

    /// Update the address of the ITS contract registered to the specified chain
    #[permission(Governance)]
    UpdateChain {
        chain: ChainNameRaw,
        its_edge_contract: Address,
    },

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
    pub frozen_status: Option<ChainStatusFilter>,
}

impl ChainStatusFilter {
    pub fn matches(&self, config: &ChainConfigResponse) -> bool {
        match self {
            ChainStatusFilter::Frozen => config.frozen,
            ChainStatusFilter::Active => !config.frozen,
        }
    }
}

impl ChainFilter {
    pub fn matches(&self, config: &ChainConfigResponse) -> bool {
        match &self.frozen_status {
            Some(frozen_status) => frozen_status.matches(config),
            None => true,
        }
    }
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
    #[returns(Vec<ChainConfigResponse>)]
    ItsChains { filter: Option<ChainFilter> },

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
