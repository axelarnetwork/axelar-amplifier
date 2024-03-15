use axelar_wasm_std::nonempty;
use cosmwasm_std::Addr;
use cw_multi_test::App;

use crate::{
    connection_router_contract::ConnectionRouterContract, multisig_contract::MultisigContract,
    rewards_contract::RewardsContract, service_registry_contract::ServiceRegistryContract,
};

pub struct Protocol {
    pub genesis_address: Addr, // holds u128::max coins, can use to send coins to other addresses
    pub governance_address: Addr,
    pub connection_router: ConnectionRouterContract,
    pub router_admin_address: Addr,
    pub multisig: MultisigContract,
    pub service_registry: ServiceRegistryContract,
    pub service_name: nonempty::String,
    pub rewards: RewardsContract,
    pub rewards_params: rewards::msg::Params,
    pub app: App,
}
