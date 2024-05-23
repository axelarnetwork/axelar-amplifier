#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{DepsMut, Empty, Env, MessageInfo, Response};
use error_stack::ResultExt;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg};
use crate::nexus;
use crate::state::{Config, GatewayStore, Store};

mod execute;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::ContractError> {
    // any version checks should be done before here

    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let nexus = deps.api.addr_validate(&msg.nexus)?;
    let router = deps.api.addr_validate(&msg.router)?;

    GatewayStore::new(deps.storage)
        .save_config(Config { nexus, router })
        .expect("config must be saved");

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response<nexus::Message>, axelar_wasm_std::ContractError> {
    let contract = Contract::new(GatewayStore::new(deps.storage));

    let res = match msg {
        ExecuteMsg::RouteMessages(msgs) => contract
            .route_to_nexus(info.sender, msgs)
            .change_context(ContractError::RouteToNexus)?,
        ExecuteMsg::RouteMessagesFromNexus(msgs) => contract
            .route_to_router(info.sender, msgs)
            .change_context(ContractError::RouteToRouter)?,
    };

    Ok(res)
}

struct Contract<S>
where
    S: Store,
{
    store: S,
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
