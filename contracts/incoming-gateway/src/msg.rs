use cosmwasm_schema::cw_serde;
use cosmwasm_std::HexBinary;

// TODO: should be some type used across contracts?
#[cw_serde]
pub struct Message {
    id: String,
    source_address: String,
    destination_address: String,
    destination_domain: String,
    payload_hash: HexBinary,
}

#[cw_serde]
pub enum ExecuteMsg {
    // Posts a message to the gateway and stores it with current validation status
    // TODO: add the ability to pass just message ID?
    ValidateMessage { msg: Message },

    // Executes a message if the message is fully validated
    // TODO: add the ability to pass just message ID?
    ExecuteMessage { msg: Message },
}
