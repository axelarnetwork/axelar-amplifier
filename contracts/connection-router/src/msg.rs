use crate::state::NewMessage;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::HexBinary;

use crate::types::GatewayDirection;

// Message is a type meant to be used in interfaces where the data can be provided by the user.
// The fields have not necessarily been validated, and should be checked prior to further processing.
#[cw_serde]
#[deprecated(note = "use NewMessage instead")]
pub struct Message {
    pub id: String, // should be globally unique
    pub source_address: String,
    pub source_chain: String,
    pub destination_address: String,
    pub destination_chain: String,
    pub payload_hash: HexBinary,
}

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
    RouteMessages(Vec<NewMessage>),
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {}
