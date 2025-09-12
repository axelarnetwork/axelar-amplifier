use cosmwasm_schema::write_api;

fn main() {
    write_api! {
        instantiate:  aleo_signature_verifier::msg::InstantiateMsg,
        migrate: aleo_signature_verifier::msg::MigrateMsg,
        execute: signature_verifier_api::msg::ExecuteMsg,
        query: signature_verifier_api::msg::QueryMsg,
    }
}
