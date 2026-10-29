use cosmwasm_schema::write_api;
use gateway_api::msg::{ExecuteMsg, QueryMsg};
use xrpl_gateway::msg::InstantiateMsg;

fn main() {
    write_api! {
        instantiate: InstantiateMsg,
        execute: ExecuteMsg,
        query: QueryMsg,
    }
}
