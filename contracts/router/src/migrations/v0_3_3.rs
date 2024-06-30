use cosmwasm_std::Storage;
use cw2::VersionError;

use crate::state;
use axelar_wasm_std::{permission_control, ContractError};
use router_api::error::Error;

pub fn migrate(storage: &mut dyn Storage) -> Result<(), ContractError> {
    let current_version = cw2::get_contract_version(storage)?;
    if current_version.version != "0.3.3" {
        Err(VersionError::WrongVersion {
            expected: "0.3.3".into(),
            found: current_version.version,
        }
        .into())
    } else {
        set_generalized_permission_control(storage)?;
        Ok(())
    }
}

fn set_generalized_permission_control(storage: &mut dyn Storage) -> error_stack::Result<(), Error> {
    let config = state::load_config(storage)?;
    permission_control::set_admin(storage, &config.admin)
        .and_then(|_| permission_control::set_governance(storage, &config.governance))
        .map_err(Error::from)?;
    Ok(())
}

#[cfg(test)]
mod test {
    use axelar_wasm_std::msg_id::MessageIdFormat;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use std::env;

    use crate::contract;
    use crate::contract::execute;
    use crate::migrations::v0_3_3::migrate;
    use crate::msg::InstantiateMsg;
    use router_api::msg::ExecuteMsg;
    use router_api::GatewayDirection;

    #[test]
    #[allow(deprecated)]
    fn migration() {
        let mut deps = mock_dependencies();
        env::set_var("CARGO_PKG_VERSION", "0.3.3");

        let admin = "admin";
        let governance = "governance";

        contract::instantiate_old(
            deps.as_mut(),
            mock_env(),
            mock_info(admin, &[]),
            InstantiateMsg {
                nexus_gateway: "nexus_gateway".to_string(),
                admin_address: admin.to_string(),
                governance_address: governance.to_string(),
            },
        )
        .unwrap();

        let msg = ExecuteMsg::RegisterChain {
            chain: "chain".parse().unwrap(),
            gateway_address: "gateway".parse().unwrap(),
            msg_id_format: MessageIdFormat::HexTxHashAndEventIndex,
        };

        // before migration no address should be able to execute this message

        assert!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info(admin, &[]),
            msg.clone(),
        )
        .is_err());

        assert!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info(governance, &[]),
            msg.clone(),
        )
        .is_err());

        //set to future version
        env::set_var("CARGO_PKG_VERSION", "0.4.0");
        assert!(migrate(&mut deps.storage).is_ok());

        // after migration only governance should be able to register a chain
        assert!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info(admin, &[]),
            msg.clone(),
        )
        .is_err());

        assert!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info(governance, &[]),
            msg.clone(),
        )
        .is_ok());

        // check that both admin and governance permissions are set correctly

        let msg = ExecuteMsg::UnfreezeChain {
            chain: "chain".parse().unwrap(),
            direction: GatewayDirection::Bidirectional,
        };

        assert!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info("no_privilege", &[]),
            msg.clone(),
        )
        .is_err());

        assert!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info(admin, &[]),
            msg.clone(),
        )
        .is_ok());

        assert!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info(governance, &[]),
            msg.clone(),
        )
        .is_ok());
    }
}
