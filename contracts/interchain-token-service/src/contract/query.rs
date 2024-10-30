use axelar_wasm_std::IntoContractError;
use cosmwasm_std::{to_json_binary, Binary, Deps};
use error_stack::{Result, ResultExt};
use router_api::ChainNameRaw;

use crate::state::{load_all_its_contracts, may_load_its_contract};

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("failed to serialize data to JSON")]
    JsonSerialization,
    #[error("state error")]
    State,
}

pub fn its_contract(deps: Deps, chain: ChainNameRaw) -> Result<Binary, Error> {
    let contract_address =
        may_load_its_contract(deps.storage, &chain).change_context(Error::State)?;
    to_json_binary(&contract_address).change_context(Error::JsonSerialization)
}

pub fn all_its_contracts(deps: Deps) -> Result<Binary, Error> {
    let contract_addresses = load_all_its_contracts(deps.storage).change_context(Error::State)?;
    to_json_binary(&contract_addresses).change_context(Error::JsonSerialization)
}
