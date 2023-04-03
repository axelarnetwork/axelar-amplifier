use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Uint128, HexBinary};

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    RegisterDomain {
        domain: String,
    },
    // registers a gateway that processes messages sent from axelar to a remote domain
    RegisterOutgoingGateway {
        domain: String,
        contract_addr: Addr,
        // if specified, takes ownership of queue
        queue_id: Option<Uint128>,
    },
    // registers a gateway that processes messages sent from a remote domain to axelar
    RegisterIncomingGateway {
        domain: String,
        contract_addr: Addr,
    },
    // removes a gateway from a domain, and deletes any owned queue
    DeregisterGateway {
        domain: String,
        contract_addr: Addr,
    },
    // routes a message to all outgoing gateways registered to the destination domain
    // can only be called by an incoming gateway
    RouteMessage {
        id: String,
        destination_domain: String,
        destination_addr: Addr,
        source_addr: Addr,
        payload_hash: HexBinary,
    },
    // returns count messages and deletes them from the gateway's queue
    // can only be called by an outgoing gateway
    ConsumeMessages {
        count: u32,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {}
