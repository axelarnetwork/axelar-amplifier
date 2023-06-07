use cosmwasm_schema::cw_serde;
use cosmwasm_std::HexBinary;

// Message is a type meant to be used in interfaces where the data can be provided by the user.
// The fields have not necessarily been validated, and should be checked prior to further processing.
#[cw_serde]
pub struct Message {
    pub id: String,
    pub source_address: String,
    pub source_domain: String,
    pub destination_address: String,
    pub destination_domain: String,
    pub payload_hash: HexBinary,
}
