use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::HexBinary;

use crate::types::MessageFlowDirection;

// Message is a type meant to be used in interfaces where the data can be provided by the user.
// The fields have not necessarily been validated, and should be checked prior to further processing.
#[cw_serde]
pub struct Message {
    pub id: String,
    pub source_address: String,
    pub source_chain: String,
    pub destination_address: String,
    pub destination_chain: String,
    pub payload_hash: HexBinary,
}

#[cw_serde]
pub struct InstantiateMsg {
    pub admin_address: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    /*
     * Router Admin Methods
     * All of the below messages can only be called by the router admin
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
    // Freezes a chain, in the specified direction. This overrides any previous frozen status. Pass None to unfreeze
    FreezeChain {
        chain: String,
        direction: MessageFlowDirection,
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
