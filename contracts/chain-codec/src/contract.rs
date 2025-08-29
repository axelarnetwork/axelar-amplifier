use axelar_wasm_std::error::ContractError;
use chain_codec_api::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Binary, Deps, DepsMut, Empty, Env, HexBinary, MessageInfo, Response,
};

use crate::encoding;
use crate::error::Error;
use crate::state::{Config, CONFIG};

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, Error> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    CONFIG.save(
        deps.storage,
        &Config {
            domain_separator: msg.domain_separator,
            multisig_prover: deps.api.addr_validate(&msg.multisig_prover)?,
        },
    )?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    Ok(match msg {
        QueryMsg::EncodeExecData {
            verifier_set,
            signers,
            payload,
        } => {
            let config = CONFIG.load(deps.storage)?;

            to_json_binary(&encoding::encode_execute_data(
                &config.domain_separator,
                &verifier_set,
                signers,
                &payload,
            )?)?
        }
        QueryMsg::ValidateAddress { address } => {
            encoding::validate_address(&address)?;

            to_json_binary(&Empty {})?
        }
        QueryMsg::PayloadDigest {
            verifier_set,
            payload,
        } => {
            let config = CONFIG.load(deps.storage)?;

            to_json_binary(&HexBinary::from(encoding::payload_digest(
                &config.domain_separator,
                &verifier_set,
                &payload,
            )?))?
        }
    })
}

#[cfg_attr(not(feature = "library"), entry_point)]
// ExecuteMsg is just Empty because we don't enable notify-signing-session for chain-codec-api,
// so we cannot call ensure_permissions
#[allow(unknown_lints, execute_without_explicit_permissions)]
pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    Ok(Response::new())
}
