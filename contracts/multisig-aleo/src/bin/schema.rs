use cosmwasm_schema::write_api;

fn main() {
    write_api! {
        instantiate: multisig_aleo::msg::InstantiateMsg,
        migrate: multisig_aleo::msg::MigrateMsg,
        execute: signature_verifier_api::msg::ExecuteMsg,
        query: signature_verifier_api::msg::QueryMsg,
    }
}
