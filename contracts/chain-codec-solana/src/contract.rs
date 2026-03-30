use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::migrate_from_version;
use chain_codec_api::error::Error;
use chain_codec_api::msg::{InstantiateMsg, QueryMsg};
use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Empty, Env, HexBinary, MessageInfo,
    Response,
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
#[migrate_from_version("1.0")]
pub fn migrate(
    _deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
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
        } => to_json_binary(&crate::solana::encode_execute_data(
            &domain_separator,
            &verifier_set,
            signers,
            &payload,
        )?)?,
        QueryMsg::ValidateAddress { address } => {
            crate::solana::validate_address(&address)?;

            to_json_binary(&Empty {})?
        }
        QueryMsg::PayloadDigest {
            domain_separator,
            verifier_set,
            payload,
            full_message_payloads: _, // we don't need this here
        } => to_json_binary(&HexBinary::from(crate::solana::payload_digest(
            &domain_separator,
            &verifier_set,
            &payload,
        )?))?,
    })
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{mock_dependencies, mock_env, message_info};
    use cosmwasm_std::Empty;
    use router_api::cosmos_addr;

    use super::*;

    #[test]
    fn migrate_sets_contract_version() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = message_info(&cosmos_addr!("sender"), &[]);

        instantiate(deps.as_mut(), env.clone(), info, InstantiateMsg {}).unwrap();

        migrate(deps.as_mut(), mock_env(), Empty {}).unwrap();

        let contract_version = cw2::get_contract_version(deps.as_mut().storage).unwrap();
        assert_eq!(contract_version.contract, CONTRACT_NAME);
        assert_eq!(contract_version.version, CONTRACT_VERSION);
    }
}
