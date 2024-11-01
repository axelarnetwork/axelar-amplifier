use cosmwasm_std::{to_json_binary, Binary, Deps};
use router_api::ChainNameRaw;

use crate::{state, TokenId};

pub fn its_contracts(deps: Deps, chain: ChainNameRaw) -> Result<Binary, state::Error> {
    let contract_address = state::may_load_its_contract(deps.storage, &chain)?;
    Ok(to_json_binary(&contract_address)?)
}

pub fn all_its_contracts(deps: Deps) -> Result<Binary, state::Error> {
    let contract_addresses = state::load_all_its_contracts(deps.storage)?;
    Ok(to_json_binary(&contract_addresses)?)
}

pub fn token_info(
    deps: Deps,
    chain: ChainNameRaw,
    token_id: TokenId,
) -> Result<Binary, state::Error> {
    let token_info = state::may_load_token_info(deps.storage, chain, token_id)?;
    Ok(to_json_binary(&token_info)?)
}

pub fn token_config(deps: Deps, token_id: TokenId) -> Result<Binary, state::Error> {
    let token_config = state::may_load_token_config(deps.storage, &token_id)?;
    Ok(to_json_binary(&token_config)?)
}
