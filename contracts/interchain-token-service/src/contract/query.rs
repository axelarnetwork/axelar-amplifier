use cosmwasm_std::{to_json_binary, Binary, Deps};
use router_api::ChainNameRaw;

use crate::state;

pub fn its_contracts(deps: Deps, chain: ChainNameRaw) -> Result<Binary, state::Error> {
    let contract_address = state::may_load_its_contract(deps.storage, &chain)?;
    Ok(to_json_binary(&contract_address)?)
}

pub fn all_its_contracts(deps: Deps) -> Result<Binary, state::Error> {
    let contract_addresses = state::load_all_its_contracts(deps.storage)?;
    Ok(to_json_binary(&contract_addresses)?)
}
