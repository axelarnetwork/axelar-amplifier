use axelar_wasm_std::{address::{validate_address, AddressFormat}, error::ContractError};
use chain_codec_api::msg::QueryMsg;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response};

use crate::error::Error;

const CONTRACT_NAME: &str = "crates.io:chain-codec-abi";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: Empty,
) -> Result<Response, Error> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    Ok(match msg {
        QueryMsg::PayloadDigest { domain_separator, signer, payload } => {
            to_json_binary(&crate::abi::payload_digest(&domain_separator, &signer, &payload)?)?
        }
        QueryMsg::EncodeExecData { domain_separator, verifier_set, signers, payload } => {
            to_json_binary(&crate::abi::encode_execute_data(&domain_separator, &verifier_set, signers, &payload)?)?
        }
        QueryMsg::ValidateAddress { address } => {
            validate_address(&address, &AddressFormat::Eip55)?;

            to_json_binary(&true)?
        },
    })
}

#[cfg(test)]
mod tests {}
