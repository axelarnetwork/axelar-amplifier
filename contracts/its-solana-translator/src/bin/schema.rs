use cosmwasm_schema::write_api;
use cosmwasm_std::Empty;
use its_msg_translator_api::QueryMsg;

fn main() {
    write_api! {
        instantiate: Empty,
        execute: Empty,
        query: QueryMsg,
    }
}
