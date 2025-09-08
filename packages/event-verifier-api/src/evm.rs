use axelar_wasm_std::fixed_size;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint256};

type Address = fixed_size::HexBinary<20>;
type Topic = fixed_size::HexBinary<32>;

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
    pub topics: Vec<Topic>,        // 1-4 topics
    pub data: HexBinary,           // arbitrary length hex data
}

#[cw_serde]
pub struct EvmEvent {
    pub transaction_hash: fixed_size::HexBinary<32>,
    pub transaction_details: Option<TransactionDetails>,
    pub events: Vec<Event>,
}
