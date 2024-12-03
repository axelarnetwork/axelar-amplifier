use axelar_wasm_std::flagset::FlagSet;
use axelar_wasm_std::msg_id::MessageIdFormat;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Storage};
use cw_storage_plus::{Index, IndexList, IndexedMap, MultiIndex};
use error_stack::{Result, ResultExt};
use router_api::error::Error;
use router_api::{Gateway, GatewayDirection};

// the below types and functions are duplicated from the state module, except
// chain names are just stored as String instead of ChainName. This is so we
// can access chains with names that are no longer valid, and were stored
// when the checks on ChainName were less restrictive
#[cw_serde]
struct ChainEndpoint {
    pub name: String,
    pub gateway: Gateway,
    pub frozen_status: FlagSet<GatewayDirection>,
    pub msg_id_format: MessageIdFormat,
}

struct ChainEndpointIndexes<'a> {
    pub gateway: GatewayIndex<'a>,
}

struct GatewayIndex<'a>(MultiIndex<'a, Addr, ChainEndpoint, String>);

impl<'a> GatewayIndex<'a> {
    pub fn new(
        idx_fn: fn(&[u8], &ChainEndpoint) -> Addr,
        pk_namespace: &'a str,
        idx_namespace: &'static str,
    ) -> Self {
        GatewayIndex(MultiIndex::new(idx_fn, pk_namespace, idx_namespace))
    }
}

impl<'a> IndexList<ChainEndpoint> for ChainEndpointIndexes<'a> {
    fn get_indexes(&'_ self) -> Box<dyn Iterator<Item = &'_ dyn Index<ChainEndpoint>> + '_> {
        let v: Vec<&dyn Index<ChainEndpoint>> = vec![&self.gateway.0];
        Box::new(v.into_iter())
    }
}

const CHAINS_PKEY: &str = "chains";
fn chain_endpoints_old<'a>() -> IndexedMap<String, ChainEndpoint, ChainEndpointIndexes<'a>> {
    return IndexedMap::new(
        CHAINS_PKEY,
        ChainEndpointIndexes {
            gateway: GatewayIndex::new(
                |_pk: &[u8], d: &ChainEndpoint| d.gateway.address.clone(),
                CHAINS_PKEY,
                "gateways",
            ),
        },
    );
}

pub fn migrate(storage: &mut dyn Storage, chains_to_remove: Vec<String>) -> Result<(), Error> {
    for chain in chains_to_remove {
        chain_endpoints_old()
            .remove(storage, chain)
            .change_context(Error::StoreFailure)?;
    }
    Ok(())
}
#[cfg(test)]
mod test {
    #![allow(deprecated)]

    use assert_ok::assert_ok;
    use axelar_wasm_std::msg_id::MessageIdFormat;
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::Addr;
    use itertools::Itertools;
    use router_api::{ChainName, Gateway, GatewayDirection};

    use super::{chain_endpoints_old, migrate, ChainEndpoint};
    use crate::state::{self, chain_endpoints};

    #[test]
    fn can_delete_chains() {
        let mut deps = mock_dependencies();
        let good_chain_names: Vec<ChainName> = ["ethereum", "avalanche"]
            .into_iter()
            .map(|name| ChainName::try_from(name).unwrap())
            .collect();
        for chain_name in &good_chain_names {
            state::chain_endpoints()
                .save(
                    deps.as_mut().storage,
                    chain_name.clone(),
                    &router_api::ChainEndpoint {
                        name: chain_name.clone(),
                        gateway: Gateway {
                            address: Addr::unchecked("gateway_address"),
                        },
                        frozen_status: GatewayDirection::None.into(),
                        msg_id_format: MessageIdFormat::HexTxHashAndEventIndex,
                    },
                )
                .unwrap();
        }

        let bad_chain_name = "some really really long chain name that is not valid";
        chain_endpoints_old()
            .save(
                deps.as_mut().storage,
                bad_chain_name.to_string(),
                &ChainEndpoint {
                    name: bad_chain_name.to_string(),
                    gateway: Gateway {
                        address: Addr::unchecked("gateway_address"),
                    },
                    frozen_status: GatewayDirection::None.into(),
                    msg_id_format: MessageIdFormat::HexTxHashAndEventIndex,
                },
            )
            .unwrap();

        assert_ok!(migrate(
            deps.as_mut().storage,
            vec![good_chain_names[0].to_string(), bad_chain_name.to_string()]
        ));

        let chains: Vec<ChainName> = assert_ok!(chain_endpoints()
            .range(
                deps.as_mut().storage,
                None,
                None,
                cosmwasm_std::Order::Ascending
            )
            .map(|item| { item.map(|(_, endpoint)| endpoint.name) })
            .try_collect());

        assert_eq!(chains, vec![good_chain_names[1].clone()]);
    }
}
