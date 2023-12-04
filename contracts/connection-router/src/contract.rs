#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};

use crate::events::RouterInstantiated;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{Config, RouterStore, Store};

mod execute;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let admin = deps.api.addr_validate(&msg.admin_address)?;
    let governance = deps.api.addr_validate(&msg.governance_address)?;
    let nexus_gateway = deps.api.addr_validate(&msg.nexus_gateway)?;

    let config = Config {
        admin: admin.clone(),
        governance: governance.clone(),
        nexus_gateway: nexus_gateway.clone(),
    };

    RouterStore::new(deps.storage)
        .save_config(config)
        .expect("must save the config");

    Ok(Response::new().add_event(
        RouterInstantiated {
            admin,
            governance,
            nexus_gateway,
        }
        .into(),
    ))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let contract = Contract::new(RouterStore::new(deps.storage));

    match msg {
        ExecuteMsg::RegisterChain {
            chain,
            gateway_address,
        } => {
            execute::require_governance(&deps, info)?;
            let gateway_address = deps.api.addr_validate(&gateway_address)?;
            execute::register_chain(deps, chain, gateway_address)
        }
        ExecuteMsg::UpgradeGateway {
            chain,
            contract_address,
        } => {
            execute::require_governance(&deps, info)?;
            let contract_address = deps.api.addr_validate(&contract_address)?;
            execute::upgrade_gateway(deps, chain, contract_address)
        }
        ExecuteMsg::FreezeChain { chain, direction } => {
            execute::require_admin(&deps, info)?;
            execute::freeze_chain(deps, chain, direction)
        }
        ExecuteMsg::UnfreezeChain { chain, direction } => {
            execute::require_admin(&deps, info)?;
            execute::unfreeze_chain(deps, chain, direction)
        }
        ExecuteMsg::RouteMessages(msgs) => Ok(contract.route_messages(info.sender, msgs)?),
    }
    .map_err(axelar_wasm_std::ContractError::from)
}

struct Contract<S>
where
    S: Store,
{
    store: S,
    #[allow(unused)]
    config: Config,
}

impl<S> Contract<S>
where
    S: Store,
{
    pub fn new(store: S) -> Self {
        let config = store.load_config().expect("config must be loaded");

        Self { store, config }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, _msg: QueryMsg) -> StdResult<Binary> {
    todo!()
}

pub mod query {}
