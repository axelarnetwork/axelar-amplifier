use cosmwasm_std::{Addr, Uint256};

pub struct Message {
    id: String,
    destination_addr: Addr,
    destination_domain: String,
    source_domain: String,
    source_addr: Addr,
    payload_hash: Uint256,
}
