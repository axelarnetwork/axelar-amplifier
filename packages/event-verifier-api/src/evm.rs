use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint256};
use router_api::Address;

#[cw_serde]
pub struct TransactionDetails {
    pub calldata: HexBinary,
    pub from: Address,
    pub to: Address,
    pub value: Uint256,
}

#[cw_serde]
pub struct Event {
    pub contract_address: Address, // address of contract emitting the event
    pub event_index: u64,          // index of the event in the transaction
    pub topics: Vec<HexBinary>,    // 1-4 topics
    pub data: HexBinary,           // arbitrary length hex data
}
