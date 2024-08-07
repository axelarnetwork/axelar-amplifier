use cosmwasm_std::{to_json_binary, Binary, Deps};
use router_api::ChainName;

use crate::msg::{AllTrustedAddressesResponse, TrustedAddressResponse};
use crate::state::{self, get_all_trusted_addresses, load_trusted_address};

pub fn trusted_address(deps: Deps, chain: ChainName) -> Result<Binary, state::Error> {
    let address = load_trusted_address(deps.storage, &chain).ok();
    to_json_binary(&TrustedAddressResponse { address }).map_err(state::Error::from)
}

pub fn all_trusted_addresses(deps: Deps) -> Result<Binary, state::Error> {
    let addresses = get_all_trusted_addresses(deps.storage)?
        .into_iter()
        .collect();
    to_json_binary(&AllTrustedAddressesResponse { addresses }).map_err(state::Error::from)
}
