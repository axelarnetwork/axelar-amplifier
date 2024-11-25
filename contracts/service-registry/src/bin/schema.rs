use cosmwasm_schema::write_api;
use service_registry::msg::InstantiateMsg;
use service_registry_api::msg::{ExecuteMsg, QueryMsg};

fn main() {
    write_api! {
        instantiate: InstantiateMsg,
        execute: ExecuteMsg,
        query: QueryMsg,
    }
}
