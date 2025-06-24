use cosmwasm_std::{Deps, Env, Binary, HexBinary};
use interchain_token_service::HubMessage;
use crate::error::ContractError;
use crate::abi::{hub_message_abi_decode, hub_message_abi_encode};

pub fn from_bytes(_deps: Deps, _env: Env, payload: HexBinary) -> Result<Binary, ContractError> {
    // Use the real abi_decode logic to convert payload to HubMessage
    let hub_message = hub_message_abi_decode(payload.as_slice())
        .map_err(|_| ContractError::SerializationFailed)?;
    cosmwasm_std::to_json_binary(&hub_message).map_err(|_| ContractError::SerializationFailed)
}

pub fn to_bytes(_deps: Deps, _env: Env, message: HubMessage) -> Result<Binary, ContractError> {
    // Use the real abi_encode logic to convert HubMessage to payload
    let payload = hub_message_abi_encode(message);
    cosmwasm_std::to_json_binary(&payload).map_err(|_| ContractError::SerializationFailed)
} 