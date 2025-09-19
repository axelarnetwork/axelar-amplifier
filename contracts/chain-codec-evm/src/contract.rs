use axelar_wasm_std::error::ContractError;
use chain_codec_api::error::Error;
use chain_codec_api::msg::{ExecuteMsg, ExecuteMsgFromProxy, QueryMsg};
use chain_codec_api::state::{load_config, save_config, Config};
use chain_codec_api::msg::InstantiateMsg;
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Addr, Binary, Deps, DepsMut, Empty, Env, HexBinary, MessageInfo, Response, Storage
};
use msgs_derive::ensure_permissions;

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

    save_config(
        deps.storage,
        &Config {
            multisig_prover: deps.api.addr_validate(&msg.multisig_prover)?,
        },
    )?;

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
            to_json_binary(&crate::evm::encode_execute_data(&domain_separator, &verifier_set, signers, &payload)?)?
        }
        QueryMsg::ValidateAddress { address } => {
            crate::evm::validate_address(&address)?;

            to_json_binary(&Empty {})?
        }
        QueryMsg::PayloadDigest {
            domain_separator,
            verifier_set,
            payload,
            full_message_payloads: _, // we don't need this here
        } => {
            to_json_binary(&HexBinary::from(crate::evm::payload_digest(&domain_separator, &verifier_set, &payload)?))?
        }
    })
}

#[cfg_attr(not(feature = "library"), entry_point)]
#[ensure_permissions(direct(prover=find_prover_address))]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    _msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    Ok(Response::new())
}

fn find_prover_address(
    storage: &dyn Storage,
    sender: &Addr,
    _msg: &ExecuteMsg,
) -> error_stack::Result<bool, Error> {
    Ok(load_config(storage).multisig_prover == *sender)
}
