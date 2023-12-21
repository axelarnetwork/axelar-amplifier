use crate::state::{ChainEndpoint, ChainName, GatewayDirection, Message};
use cosmwasm_schema::{cw_serde, QueryResponses};

#[cw_serde]
pub struct InstantiateMsg {
    // admin controls freezing and unfreezing a chain
    pub admin_address: String,
    // governance votes on chains being added or upgraded
    pub governance_address: String,
    // the address of the nexus gateway
    pub nexus_gateway: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    /*
     * Governance Methods
     * All of the below messages can only be called by governance
     */
    // Registers a new chain with the router
    RegisterChain {
        chain: ChainName,
        gateway_address: String,
    },
    // Changes the gateway address associated with a particular chain
    UpgradeGateway {
        chain: ChainName,
        contract_address: String,
    },

    /*
     * Router Admin Methods
     * All of the below messages can only be called by the router admin
     */
    // Freezes a chain, in the specified direction.
    FreezeChain {
        chain: ChainName,
        direction: GatewayDirection,
    },
    // Unfreezes a chain, in the specified direction.
    UnfreezeChain {
        chain: ChainName,
        direction: GatewayDirection,
    },

    /*
     * Gateway Messages
     * The below messages can only be called by registered gateways
     */
    // Routes a message to all outgoing gateways registered to the destination domain.
    // Called by an incoming gateway
    RouteMessages(Vec<Message>),
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(ChainEndpoint)]
    GetChainInfo(ChainName),
}
