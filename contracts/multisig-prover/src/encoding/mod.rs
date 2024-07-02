pub mod abi;
pub mod rkyv;

use cosmwasm_schema::cw_serde;

#[cw_serde]
#[derive(Copy)]
pub enum Encoder {
    Abi,
    Bcs,
    Rkyv,
}
