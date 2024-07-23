use axelar_wasm_std::nonempty;
use cosmwasm_std::Addr;
use cw_multi_test::App;

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
    pub app: App,
}
