use cosmwasm_std::{Addr, Uint256};

pub struct Message {
    _id: String,
    _destination_addr: Addr,
    _destination_domain: String,
    _source_domain: String,
    _source_addr: Addr,
    _payload_hash: Uint256,
}
