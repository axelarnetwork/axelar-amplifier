use std::fmt::Debug;
use std::ops::Deref;

use axelar_core_std::nexus;
use axelar_core_std::query::AxelarQueryMsg;
use axelar_wasm_std::nonempty;
use cosmwasm_std::testing::{MockApi, MockStorage};
use cosmwasm_std::{
    Addr, Api, Binary, BlockInfo, CustomQuery, Deps, DepsMut, Empty, Querier, QuerierWrapper,
    Storage,
};
use cw_multi_test::{App, AppResponse, BankKeeper, CosmosRouter, Module, WasmKeeper};
use serde::de::DeserializeOwned;

use crate::coordinator_contract::CoordinatorContract;
use crate::multisig_contract::MultisigContract;
use crate::rewards_contract::RewardsContract;
use crate::router_contract::RouterContract;
use crate::service_registry_contract::ServiceRegistryContract;

pub struct Protocol {
    pub genesis_address: Addr, // holds u128::max coins, can use to send coins to other addresses
    pub governance_address: Addr,
    pub router: RouterContract,
    pub router_admin_address: Addr,
    pub multisig: MultisigContract,
    pub coordinator: CoordinatorContract,
    pub service_registry: ServiceRegistryContract,
    pub service_name: nonempty::String,
    pub rewards: RewardsContract,
    pub rewards_params: rewards::msg::Params,
    pub app: AxelarApp,
}

pub type AxelarApp =
    App<BankKeeper, MockApi, MockStorage, AxelarModule, WasmKeeper<Empty, AxelarQueryMsg>>;

#[allow(clippy::type_complexity)]
pub struct AxelarModule {
    pub tx_hash_and_nonce: Box<dyn Fn(&BlockInfo) -> anyhow::Result<Binary>>,
    pub is_chain_registered: Box<dyn Fn(String) -> anyhow::Result<Binary>>,
}

impl Module for AxelarModule {
    type ExecT = Empty;
    type QueryT = AxelarQueryMsg;
    type SudoT = Empty;

    fn execute<ExecC, QueryC>(
        &self,
        _api: &dyn Api,
        _storage: &mut dyn Storage,
        _router: &dyn CosmosRouter<ExecC = ExecC, QueryC = QueryC>,
        _block: &BlockInfo,
        _sender: Addr,
        _msg: Self::ExecT,
    ) -> anyhow::Result<AppResponse>
    where
        ExecC: Debug + Clone + PartialEq + schemars::JsonSchema + DeserializeOwned + 'static,
        QueryC: CustomQuery + DeserializeOwned + 'static,
    {
        unimplemented!()
    }

    fn sudo<ExecC, QueryC>(
        &self,
        _api: &dyn Api,
        _storage: &mut dyn Storage,
        _router: &dyn CosmosRouter<ExecC = ExecC, QueryC = QueryC>,
        _block: &BlockInfo,
        _msg: Self::SudoT,
    ) -> anyhow::Result<AppResponse>
    where
        ExecC: Debug + Clone + PartialEq + schemars::JsonSchema + DeserializeOwned + 'static,
        QueryC: CustomQuery + DeserializeOwned + 'static,
    {
        unimplemented!()
    }

    fn query(
        &self,
        _: &dyn Api,
        _: &dyn Storage,
        _: &dyn Querier,
        block: &BlockInfo,
        request: Self::QueryT,
    ) -> anyhow::Result<Binary> {
        match request {
            AxelarQueryMsg::Nexus(query) => match query {
                nexus::query::QueryMsg::TxHashAndNonce {} => (self.tx_hash_and_nonce)(block),
                nexus::query::QueryMsg::IsChainRegistered { chain } => {
                    (self.is_chain_registered)(chain)
                }
                _ => unreachable!("unexpected nexus message {:?}", query),
            },
            _ => unreachable!("unexpected query request {:?}", request),
        }
    }
}

pub fn emptying_deps<'a>(deps: &'a Deps<AxelarQueryMsg>) -> Deps<'a, Empty> {
    Deps {
        storage: deps.storage,
        api: deps.api,
        querier: QuerierWrapper::new(deps.querier.deref()),
    }
}

pub fn emptying_deps_mut<'a>(deps: &'a mut DepsMut<AxelarQueryMsg>) -> DepsMut<'a, Empty> {
    DepsMut {
        storage: deps.storage,
        api: deps.api,
        querier: QuerierWrapper::new(deps.querier.deref()),
    }
}
