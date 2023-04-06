use crate::state::{Domain, Message};
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::HexBinary;

#[cw_serde]
pub struct InstantiateMsg {
    pub admin_address: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    /*
     * Router Admin Methods
     * All of the below methods can only be called by the router admin
     */
    // Registers a new domain with the router
    RegisterDomain {
        domain: String,
    },
    // Registers a gateway that processes messages sent from axelar to a remote domain.
    RegisterOutgoingGateway {
        domain: String,
        contract_address: String,
    },
    // Registers a gateway that processes messages sent from a remote domain to axelar
    RegisterIncomingGateway {
        domain: String,
        contract_address: String,
    },
    // Deregisters an entire domain. No messages can be sent from or to this domain.
    // The queue of incoming messages is left unaltered, and can be later reclaimed by registering a domain
    // with the same identifier
    DeregisterDomain {
        domain: String,
    },
    // Redelivers a given message. This will enqueue a given message on the destination
    // domain's queue. The message id and contents must exactly match a previously routed message.
    // Set redelivered to false. The router will set redelivered to true before enqueing the message
    RedeliverMessage {
        msg: Message,
    },

    /*
     * Gateway Methods
     * The below methods can only be called by registered gateways
     */
    // Routes a message to all outgoing gateways registered to the destination domain.
    // Called by an incoming gateway
    RouteMessage {
        id: String, // ids must be unique per source domain
        destination_domain: String,
        destination_address: String,
        source_address: String,
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
pub enum QueryMsg {
    #[returns(Vec<(String,Domain)>)]
    GetDomains {},

    // returns not yet consumed messages in FIFO order
    #[returns(Vec<Message>)]
    GetPendingMessages { domain: String },
}
