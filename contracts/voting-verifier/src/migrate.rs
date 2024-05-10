use axelar_wasm_std::nonempty;
use cosmwasm_std::{DepsMut, Response};

use crate::state::{Config, CONFIG};

pub fn set_source_gateway_address(
    deps: DepsMut,
    source_gateway_address: nonempty::String,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let old_config = CONFIG.load(deps.storage)?;
    let new_config = Config {
        source_gateway_address,
        ..old_config
    };
    CONFIG.save(deps.storage, &new_config)?;

    Ok(Response::default())
}

#[cfg(test)]
mod test {

    use axelar_wasm_std::{msg_id::MessageIdFormat, Threshold};
    use cosmwasm_std::{testing::mock_dependencies, Addr};

    use super::*;

    #[test]
    fn successfuly_migrate_source_gateway_address() {
        let mut deps = mock_dependencies();

        let initial_config = Config {
            governance: Addr::unchecked("governance"),
            service_name: "service_name".parse().unwrap(),
            service_registry_contract: Addr::unchecked("service_registry_address"),
            source_gateway_address: "initial_source_gateway_address".parse().unwrap(),
            voting_threshold: Threshold::try_from((2, 3)).unwrap().try_into().unwrap(),
            block_expiry: 100,
            confirmation_height: 100,
            source_chain: "source-chain".parse().unwrap(),
            rewards_contract: Addr::unchecked("rewards_address"),
            msg_id_format: MessageIdFormat::HexTxHashAndEventIndex,
        };
        CONFIG.save(deps.as_mut().storage, &initial_config).unwrap();

        let new_source_gateway_address: nonempty::String =
            "new_source_gateway_address".parse().unwrap();
        let response =
            set_source_gateway_address(deps.as_mut(), new_source_gateway_address.clone()).unwrap();

        assert_eq!(response, Response::default());

        let actual_config = CONFIG.load(deps.as_ref().storage).unwrap();
        assert_eq!(
            actual_config,
            Config {
                source_gateway_address: new_source_gateway_address,
                ..initial_config
            }
        )
    }
}
