use cosmwasm_schema::cw_serde;
use cosmwasm_std::Binary;

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    CallContract {
        contract_address: String,
        destination_chain: String,
        payload: Binary,
    },
}

// #[cw_serde]
// #[derive(QueryResponses)]
// pub enum QueryMsg {
//     #[returns(ActiveWorkers)]
//     GetActiveWorkers { service_name: String },
// }

// #[cw_serde]
// pub struct ActiveWorkers {
//     pub workers: Vec<u8>,
// }
