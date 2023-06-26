use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::HexBinary;

// Message is a type meant to be used in interfaces where the data can be provided by the user.
// The fields have not necessarily been validated, and should be checked prior to further processing.
#[cw_serde]
pub struct Message {
    pub id: String,
    pub source_address: String,
    pub source_domain: String,
    pub destination_address: String,
    pub destination_domain: String,
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
    // Registers a new domain with the router
    RegisterDomain {
        domain: String,
        incoming_gateway_address: String,
        outgoing_gateway_address: String,
    },
    // Registers a gateway that processes messages sent from axelar to a remote domain.
    UpgradeOutgoingGateway {
        domain: String,
        contract_address: String,
    },
    // Registers a gateway that processes messages sent from a remote domain to axelar
    UpgradeIncomingGateway {
        domain: String,
        contract_address: String,
    },
    // Deregisters an entire domain. No messages can be sent from or to this domain.
    // The queue of incoming messages is left unaltered, and can be later reclaimed by registering a domain
    // with the same identifier
    FreezeDomain {
        domain: String,
    },
    FreezeIncomingGateway {
        domain: String,
    },
    FreezeOutgoingGateway {
        domain: String,
    },
    UnfreezeDomain {
        domain: String,
    },
    UnfreezeIncomingGateway {
        domain: String,
    },
    UnfreezeOutgoingGateway {
        domain: String,
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
