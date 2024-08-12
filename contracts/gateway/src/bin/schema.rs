use cosmwasm_schema::write_api;
use gateway::msg::InstantiateMsg;
use gateway_api::msg::{ExecuteMsg, QueryMsg};

fn main() {
    write_api! {
        instantiate: InstantiateMsg,
        execute: ExecuteMsg,
        query: QueryMsg,
    }
}
