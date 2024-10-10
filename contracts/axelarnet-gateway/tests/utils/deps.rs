use std::marker::PhantomData;

use axelar_core_std::nexus::query::QueryMsg;
use axelar_core_std::query::AxelarQueryMsg;
use cosmwasm_std::testing::{MockApi, MockQuerier, MockQuerierCustomHandlerResult, MockStorage};
use cosmwasm_std::{
    Api, ContractResult, CustomQuery, Deps, DepsMut, Empty, OwnedDeps, Querier, QuerierWrapper,
    Storage, SystemResult,
};
use serde_json::json;

pub fn mock_axelar_dependencies(
) -> OwnedDeps<MockStorage, MockApi, MockQuerier<AxelarQueryMsg>, AxelarQueryMsg> {
    OwnedDeps {
        storage: MockStorage::default(),
        api: MockApi::default(),
        querier: MockQuerier::<AxelarQueryMsg>::new(&[("contract", &[])]),
        custom_query_type: PhantomData,
    }
}

pub fn axelar_query_handler(
    tx_hash: [u8; 32],
    nonce: u32,
    is_chain_registered: bool,
) -> impl Fn(&AxelarQueryMsg) -> MockQuerierCustomHandlerResult {
    move |query| {
        let result = match query {
            AxelarQueryMsg::Nexus(nexus_query) => match nexus_query {
                QueryMsg::TxHashAndNonce {} => json!({
                    "tx_hash": tx_hash,
                    "nonce": nonce,
                }),
                QueryMsg::IsChainRegistered { chain: _ } => json!({
                    "is_registered": is_chain_registered
                }),
                _ => unreachable!("unexpected nexus query {:?}", nexus_query),
            },
            _ => unreachable!("unexpected query request {:?}", query),
        }
        .to_string()
        .as_bytes()
        .into();

        SystemResult::Ok(ContractResult::Ok(result))
    }
}

pub trait OwnedDepsExt {
    fn as_default_mut(&mut self) -> DepsMut<Empty>;
    fn as_default_deps(&self) -> Deps<Empty>;
}

impl<S: Storage, A: Api, Q: Querier, C: CustomQuery> OwnedDepsExt for OwnedDeps<S, A, Q, C> {
    fn as_default_mut(&'_ mut self) -> DepsMut<'_, Empty> {
        DepsMut {
            storage: &mut self.storage,
            api: &self.api,
            querier: QuerierWrapper::new(&self.querier),
        }
    }

    fn as_default_deps(&'_ self) -> Deps<'_, Empty> {
        Deps {
            storage: &self.storage,
            api: &self.api,
            querier: QuerierWrapper::new(&self.querier),
        }
    }
}
