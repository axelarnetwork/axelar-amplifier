use cosmwasm_std::{Order, Storage};
use cw_storage_plus::Bound;
use error_stack::{Result, ResultExt};
use router_api::error::Error;
use router_api::{ChainEndpoint, ChainName};

use crate::state::chain_endpoints;

// Pagination limits
const DEFAULT_LIMIT: u32 = u32::MAX;

pub fn chain_info(storage: &dyn Storage, chain: ChainName) -> Result<ChainEndpoint, Error> {
    chain_endpoints()
        .may_load(storage, chain)
        .change_context(Error::StoreFailure)?
        .ok_or(Error::ChainNotFound.into())
}

pub fn chains(
    storage: &dyn Storage,
    start_after: Option<ChainName>,
    limit: Option<u32>,
) -> Result<Vec<ChainEndpoint>, Error> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT) as usize;
    let start = start_after.map(Bound::exclusive);

    chain_endpoints()
        .range(storage, start, None, Order::Ascending)
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
    use cosmwasm_std::testing::{mock_dependencies, MockApi};
    use router_api::error::Error;
    use router_api::{ChainEndpoint, ChainName, Gateway, GatewayDirection};

    use super::chain_info;
    use crate::state::chain_endpoints;

    #[test]
    fn should_get_chain_info() {
        let mut deps = mock_dependencies();
        let chain_name: ChainName = "Ethereum".try_into().unwrap();
        let endpoint = ChainEndpoint {
            name: chain_name.clone(),
            gateway: Gateway {
                address: MockApi::default().addr_make("some gateway"),
            },
            frozen_status: FlagSet::from(GatewayDirection::None),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        };

        assert!(chain_endpoints()
            .save(deps.as_mut().storage, chain_name.clone(), &endpoint)
            .is_ok());
        let result = chain_info(deps.as_ref().storage, chain_name);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), endpoint);
    }

    #[test]
    fn get_non_existent_chain_info() {
        let deps = mock_dependencies();
        let chain_name: ChainName = "Ethereum".try_into().unwrap();
        let result = chain_info(deps.as_ref().storage, chain_name);
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
                    address: MockApi::default().addr_make(format!("{} gateway", chain).as_str()),
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
        let result = super::chains(deps.as_ref().storage, None, None).unwrap();
        assert_eq!(result.len(), 4);
        assert_eq!(result, endpoints);

        // with limit
        let result = super::chains(deps.as_ref().storage, None, Some(2)).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result, vec![endpoints[0].clone(), endpoints[1].clone()]);

        // with page
        let result = super::chains(
            deps.as_ref().storage,
            Some("c-chain".parse().unwrap()),
            Some(2),
        )
        .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result, vec![endpoints[3].clone()]);

        // start after the last chain
        let result = super::chains(
            deps.as_ref().storage,
            Some("d-chain".parse().unwrap()),
            Some(2),
        )
        .unwrap();
        assert_eq!(result.len(), 0);

        // with a key out of the scope
        let result = super::chains(
            deps.as_ref().storage,
            Some("e-chain".parse().unwrap()),
            Some(2),
        )
        .unwrap();
        assert_eq!(result.len(), 0);
    }
}
