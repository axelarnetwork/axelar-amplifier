use cosmwasm_schema::cw_serde;
use service_interface::msg::ActionMessage;

#[cw_serde]
pub enum ExecuteMsg {
    AddMessageToBatch { message: ActionMessage },
}
