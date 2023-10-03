use crate::state::{GatewayDirection, Message};
use cosmwasm_schema::{cw_serde, QueryResponses};

#[cw_serde]
pub struct InstantiateMsg {
    // admin controls freezing and unfreezing a chain
    pub admin_address: String,
    // governance votes on chains being added or upgraded
    pub governance_address: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    /*
     * Governance Methods
     * All of the below messages can only be called by governance
     */
    // Registers a new chain with the router
    RegisterChain {
        chain: String,
        gateway_address: String,
    },
    // Changes the gateway address associated with a particular chain
    UpgradeGateway {
        chain: String,
        contract_address: String,
    },

    /*
     * Router Admin Methods
     * All of the below messages can only be called by the router admin
     */
    // Freezes a chain, in the specified direction.
    FreezeChain {
        chain: String,
        direction: GatewayDirection,
    },
    // Unfreezes a chain, in the specified direction.
    UnfreezeChain {
        chain: String,
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
pub enum QueryMsg {}
