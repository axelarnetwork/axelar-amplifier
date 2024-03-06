use connection_router_api::error::Error;
use connection_router_api::{ChainEndpoint, ChainName};
use cosmwasm_std::Deps;
use error_stack::{Result, ResultExt};

use crate::state::chain_endpoints;

pub fn get_chain_info(deps: Deps, chain: ChainName) -> Result<ChainEndpoint, Error> {
    chain_endpoints()
        .may_load(deps.storage, chain)
        .change_context(Error::StoreFailure)?
        .ok_or(Error::ChainNotFound.into())
}

#[cfg(test)]
mod test {
    use axelar_wasm_std::flagset::FlagSet;
    use connection_router_api::error::Error;
    use connection_router_api::{ChainEndpoint, ChainName, Gateway, GatewayDirection};
    use cosmwasm_std::{testing::mock_dependencies, Addr};

    use crate::state::chain_endpoints;

    use super::get_chain_info;

    #[test]
    fn should_get_chain_info() {
        let mut deps = mock_dependencies();
        let chain_name: ChainName = "Ethereum".to_string().try_into().unwrap();
        let chain_info = ChainEndpoint {
            name: chain_name.clone(),
            gateway: Gateway {
                address: Addr::unchecked("some gateway"),
            },
            frozen_status: FlagSet::from(GatewayDirection::None),
        };

        assert!(chain_endpoints()
            .save(deps.as_mut().storage, chain_name.clone(), &chain_info)
            .is_ok());
        let result = get_chain_info(deps.as_ref(), chain_name);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), chain_info);
    }

    #[test]
    fn get_non_existent_chain_info() {
        let deps = mock_dependencies();
        let chain_name: ChainName = "Ethereum".to_string().try_into().unwrap();
        let result = get_chain_info(deps.as_ref(), chain_name);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().current_context(), &Error::ChainNotFound);
    }
}
