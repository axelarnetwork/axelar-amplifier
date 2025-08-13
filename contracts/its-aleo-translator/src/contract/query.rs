use cosmwasm_std::{Binary, HexBinary};
use interchain_token_service_std::HubMessage;
use snarkvm_cosmwasm::prelude::Network;

use crate::aleo::{aleo_inbound_hub_message, aleo_outbound_hub_message};
use crate::error::ContractError;

pub fn from_bytes<N: Network>(payload: HexBinary) -> Result<Binary, ContractError> {
    let hub_message =
        aleo_outbound_hub_message::<N>(payload).map_err(|_| ContractError::SerializationFailed)?;
    cosmwasm_std::to_json_binary(&hub_message).map_err(|_| ContractError::SerializationFailed)
}

pub fn to_bytes<N: Network>(message: HubMessage) -> Result<Binary, ContractError> {
    let payload =
        aleo_inbound_hub_message::<N>(message).map_err(|_| ContractError::SerializationFailed)?;
    cosmwasm_std::to_json_binary(&payload).map_err(|_| ContractError::SerializationFailed)
}
