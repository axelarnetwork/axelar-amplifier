use cosmwasm_schema::write_api;
use router::msg::InstantiateMsg;
use router_api::msg::{ExecuteMsg, QueryMsg};

fn main() {
    write_api! {
        instantiate: InstantiateMsg,
        execute: ExecuteMsg,
        query: QueryMsg,
    }
}
