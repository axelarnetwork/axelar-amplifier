use cosmwasm_std::{Binary, Deps, Env, HexBinary};
use interchain_token::HubMessage;

use crate::abi::{hub_message_abi_decode, hub_message_abi_encode};
use crate::error::ContractError;

pub fn from_bytes(_deps: Deps, _env: Env, payload: HexBinary) -> Result<Binary, ContractError> {
    let hub_message = hub_message_abi_decode(payload.as_slice())
        .map_err(|_| ContractError::SerializationFailed)?;
    cosmwasm_std::to_json_binary(&hub_message).map_err(|_| ContractError::SerializationFailed)
}

pub fn to_bytes(_deps: Deps, _env: Env, message: HubMessage) -> Result<Binary, ContractError> {
    let payload = hub_message_abi_encode(message);
    cosmwasm_std::to_json_binary(&payload).map_err(|_| ContractError::SerializationFailed)
}
