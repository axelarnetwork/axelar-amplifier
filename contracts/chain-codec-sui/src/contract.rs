use axelar_wasm_std::error::ContractError;
use chain_codec_api::error::Error;
use chain_codec_api::msg::QueryMsg;
use chain_codec_api::msg::InstantiateMsg;
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Binary, Deps, DepsMut, Empty, Env, HexBinary, MessageInfo, Response
};

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, Error> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    Ok(match msg {
        QueryMsg::EncodeExecData {
            domain_separator,
            verifier_set,
            signers,
            payload,
        } => {
            to_json_binary(&crate::sui::encode_execute_data(&domain_separator, &verifier_set, signers, &payload)?)?
        }
        QueryMsg::ValidateAddress { address } => {
            crate::sui::validate_address(&address)?;

            to_json_binary(&Empty {})?
        }
        QueryMsg::PayloadDigest {
            domain_separator,
            verifier_set,
            payload,
            full_message_payloads: _, // we don't need this here
        } => {
            to_json_binary(&HexBinary::from(crate::sui::payload_digest(&domain_separator, &verifier_set, &payload)?))?
        }
    })
}