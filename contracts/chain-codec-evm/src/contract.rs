use axelar_wasm_std::address::{validate_address, AddressFormat};
use axelar_wasm_std::error::ContractError;
use chain_codec_api::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response};

use crate::abi;
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

            to_json_binary(&crate::abi::encode_execute_data(
                &config.domain_separator,
                &verifier_set,
                signers,
                &payload,
            )?)?
        }
        QueryMsg::ValidateAddress { address } => {
            validate_address(&address, &AddressFormat::Eip55)?;

            to_json_binary(&Empty {})?
        }
    })
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage).map_err(ContractError::from)?;

    match msg.ensure_permissions(
        deps.storage,
        &_info.sender,
        |_, _| -> error_stack::Result<_, ContractError> { Ok(config.multisig_prover.clone()) },
    )? {
        ExecuteMsg::PayloadDigest { signer, payload } => {
            let digest = abi::payload_digest(&config.domain_separator, &signer, &payload)?;
            Ok(Response::new().set_data(digest))
        }
    }
}
