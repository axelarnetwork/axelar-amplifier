// because each test file is a module, the compiler complains about unused imports if one of the files doesn't use them.
// This circumvents that issue.
#![allow(dead_code)]

use std::marker::PhantomData;
use std::ops::Deref;

use axelar_core_std::nexus::query::QueryMsg;
use axelar_core_std::query::AxelarQueryMsg;
use cosmwasm_std::testing::{MockApi, MockQuerier, MockQuerierCustomHandlerResult, MockStorage};
use cosmwasm_std::{ContractResult, Deps, DepsMut, Empty, OwnedDeps, QuerierWrapper, SystemResult};
#[allow(unused_imports)]
pub use execute::*;
pub use instantiate::*;
use serde_json::json;

mod execute;
mod instantiate;
pub mod messages;
pub mod params;

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

pub fn emptying_deps_mut<'a>(deps: &'a mut DepsMut<AxelarQueryMsg>) -> DepsMut<'a, Empty> {
    DepsMut {
        storage: deps.storage,
        api: deps.api,
        querier: QuerierWrapper::new(deps.querier.deref()),
    }
}

pub fn emptying_deps<'a>(deps: &'a Deps<AxelarQueryMsg>) -> Deps<'a, Empty> {
    Deps {
        storage: deps.storage,
        api: deps.api,
        querier: QuerierWrapper::new(deps.querier.deref()),
    }
}
