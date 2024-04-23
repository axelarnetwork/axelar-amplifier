use cosmwasm_std::{Deps, Order};
use cw_storage_plus::Bound;

use error_stack::{Result, ResultExt};
use router_api::error::Error;
use router_api::{ChainEndpoint, ChainName};

use crate::state::chain_endpoints;

// Pagination limits
const DEFAULT_LIMIT: u32 = u32::MAX;

pub fn get_chain_info(deps: Deps, chain: ChainName) -> Result<ChainEndpoint, Error> {
    chain_endpoints()
        .may_load(deps.storage, chain)
        .change_context(Error::StoreFailure)?
        .ok_or(Error::ChainNotFound.into())
}

pub fn chains(
    deps: Deps,
    start_after: Option<ChainName>,
    limit: Option<u32>,
) -> Result<Vec<ChainEndpoint>, Error> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT) as usize;
    let start = start_after.map(Bound::exclusive);

    chain_endpoints()
        .range(deps.storage, start, None, Order::Ascending)
        .take(limit)
        .map(|item| {
            item.map(|(_, endpoint)| endpoint)
                .change_context(Error::StoreFailure)
        })
        .collect()
}

#[cfg(test)]
mod test {
    use axelar_wasm_std::flagset::FlagSet;
    use cosmwasm_std::{testing::mock_dependencies, Addr};
    use router_api::error::Error;
    use router_api::{ChainEndpoint, ChainName, Gateway, GatewayDirection};

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
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
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

    #[test]
    fn paginated_chains() {
        let mut deps = mock_dependencies();
        let chains: Vec<ChainName> = vec![
            "a-chain".parse().unwrap(),
            "b-chain".parse().unwrap(),
            "c-chain".parse().unwrap(),
            "d-chain".parse().unwrap(),
        ];

        let endpoints: Vec<ChainEndpoint> = chains
            .iter()
            .map(|chain| ChainEndpoint {
                name: chain.clone(),
                gateway: Gateway {
                    address: Addr::unchecked(format!("{} gateway", chain)),
                },
                frozen_status: FlagSet::from(GatewayDirection::None),
                msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
            })
            .collect();

        // save end points to storage
        for chain_info in endpoints.iter() {
            assert!(chain_endpoints()
                .save(deps.as_mut().storage, chain_info.name.clone(), chain_info)
                .is_ok());
        }

        // no pagination
        let result = super::chains(deps.as_ref(), None, None).unwrap();
        assert_eq!(result.len(), 4);
        assert_eq!(result, endpoints);

        // with limit
        let result = super::chains(deps.as_ref(), None, Some(2)).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result, vec![endpoints[0].clone(), endpoints[1].clone()]);

        // with page
        let result =
            super::chains(deps.as_ref(), Some("c-chain".parse().unwrap()), Some(2)).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result, vec![endpoints[3].clone()]);

        // start after the last chain
        let result =
            super::chains(deps.as_ref(), Some("d-chain".parse().unwrap()), Some(2)).unwrap();
        assert_eq!(result.len(), 0);

        // with a key out of the scope
        let result =
            super::chains(deps.as_ref(), Some("e-chain".parse().unwrap()), Some(2)).unwrap();
        assert_eq!(result.len(), 0);
    }
}
