use lazy_static::lazy_static;
use router_api::{address, Address};

pub const AXELARNET: &str = "axelarnet";
pub const ROUTER: &str = "router";
pub const GATEWAY: &str = "gateway";
pub const GOVERNANCE: &str = "governance";
pub const ADMIN: &str = "admin";
pub const OPERATOR: &str = "operator";

lazy_static! {
    pub static ref MOCK_ADDRESS: Address = address!("0x1234567890123456789012345678901234567890");
}
