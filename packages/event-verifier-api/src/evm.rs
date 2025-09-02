use axelar_wasm_std::fixed_size;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint256};

type Address = fixed_size::HexBinary<20>;
type Topic = fixed_size::HexBinary<32>;

// TODO: make some of the types here stricter to enforce invariants, i.e. topics are always 32 bytes,
// addresses have a certain structure, etc.
// Also, be consistent with 0x vs no 0x prefix
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
