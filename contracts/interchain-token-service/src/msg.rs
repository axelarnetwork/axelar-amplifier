use std::collections::HashMap;

use axelar_wasm_std::nonempty;
use axelarnet_gateway::AxelarExecutableMsg;
use cosmwasm_schema::{cw_serde, QueryResponses};
use msgs_derive::EnsurePermissions;
use router_api::{Address, ChainNameRaw};

use crate::state::{GlobalTokenConfig, TokenInstance};
use crate::TokenId;

#[cw_serde]
pub struct InstantiateMsg {
    pub governance_address: String,
    pub admin_address: String,
    /// The address of the axelarnet-gateway contract on Amplifier
    pub axelarnet_gateway_address: String,
    /// Addresses of the ITS edge contracts on connected chains
    pub its_contracts: HashMap<ChainNameRaw, Address>,
}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    /// Execute a cross-chain message received by the axelarnet-gateway from another chain
    #[permission(Specific(gateway))]
    Execute(AxelarExecutableMsg),
    /// Register the ITS contract address of another chain. Each chain's ITS contract has to be whitelisted before
    /// ITS Hub can send cross-chain messages to it, or receive messages from it.
    /// If an ITS contract is already set for the chain, an error is returned.
    #[permission(Governance)]
    RegisterItsContract {
        chain: ChainNameRaw,
        address: Address,
    },
    /// Deregister the ITS contract address for the given chain.
    /// The admin is allowed to remove the ITS address of a chain for emergencies.
    #[permission(Elevated)]
    DeregisterItsContract { chain: ChainNameRaw },

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
    /// Set the chain configuration for a chain.
    #[permission(Governance)]
    SetChainConfig {
        chain: ChainNameRaw,
        max_uint: nonempty::Uint256, // The maximum uint value that is supported by the chain's token standard
        max_target_decimals: u8, // The maximum number of decimals that is preserved when deploying a token to another chain where smaller uint values are used
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// Query the ITS contract address registered for a chain
    #[returns(Option<Address>)]
    ItsContract { chain: ChainNameRaw },
    /// Query all registered ITS contract addresses
    #[returns(HashMap<ChainNameRaw, Address>)]
    AllItsContracts,
    /// Query the token info for a specific token instantiation on a chain
    #[returns(Option<TokenInstance>)]
    TokenInstance {
        chain: ChainNameRaw,
        token_id: TokenId,
    },
    /// Query the global token config for a token
    #[returns(Option<GlobalTokenConfig>)]
    TokenConfig { token_id: TokenId },
}
