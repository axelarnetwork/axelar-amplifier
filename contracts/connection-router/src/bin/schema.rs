use connection_router_api::msg::{ExecuteMsg, QueryMsg};
use cosmwasm_schema::write_api;

use connection_router::msg::InstantiateMsg;

fn main() {
    write_api! {
        instantiate: InstantiateMsg,
        execute: ExecuteMsg,
        query: QueryMsg,
    }
}
