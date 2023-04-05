use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, HexBinary, Uint128};

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    /*
     * Router Admin Methods
     * All of the below Register* methods can only be called by the router admin
     */
    // Registers a new domain with the router
    RegisterDomain {
        domain: String,
    },
    // Registers a gateway that processes messages sent from axelar to a remote domain.
    // Returns an identifier for the queue corresponding to this gateway
    RegisterOutgoingGateway {
        domain: String,
        contract_addr: Addr,
        // If specified, takes ownership of queue. The previous owner of the queue will no longer receive any messages
        queue_id: Option<Uint128>,
    },
    // Registers a gateway that processes messages sent from a remote domain to axelar
    RegisterIncomingGateway {
        domain: String,
        contract_addr: Addr,
    },
    // Removes a gateway from a domain, and deletes any still owned queue
    DeregisterGateway {
        domain: String,
        contract_addr: Addr,
    },

    /*
     * Gateway Methods
     * The below methods can only be called by registered gateways
     */
    // Routes a message to all outgoing gateways registered to the destination domain.
    // Called by an incoming gateway
    RouteMessage {
        id: String,
        destination_domain: String,
        destination_addr: Addr,
        source_addr: Addr,
        payload_hash: HexBinary,
    },
    // Returns count messages and deletes them from the gateway's queue.
    // Called by an outgoing gateway
    ConsumeMessages {
        count: u32,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {}
