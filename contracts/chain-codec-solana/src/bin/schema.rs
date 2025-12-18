use chain_codec_solana::contract;
use cosmwasm_schema::write_api;

fn main() {
    write_api! {
        instantiate: chain_codec_api::msg::InstantiateMsg,
        query: chain_codec_api::msg::QueryMsg,
    }
}
