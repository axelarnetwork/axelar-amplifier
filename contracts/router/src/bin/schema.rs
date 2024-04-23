use cosmwasm_schema::write_api;
use router_api::msg::{ExecuteMsg, QueryMsg};

use router::msg::InstantiateMsg;

fn main() {
    write_api! {
        instantiate: InstantiateMsg,
        execute: ExecuteMsg,
        query: QueryMsg,
    }
}
