use cosmwasm_std::Storage;
use cw_storage_plus::Map;
use error_stack::{report, Result};
use service_registry_api::error::ContractError;
use service_registry_api::Service;

type ServiceName = String;

const SERVICES: Map<&ServiceName, Service> = Map::new("services");

// Although the SERVICES struct has not changed, it is private, so
// the migration cannot manipulate it directly. We need to test that
// this migration can get the contract out of an invalid state
// where an entry that exists in SERVICES, does not exist in
// AUTHORIZED_VERIFIER_COUNT. This function allows us to get into
// that invalid state (since we cannot get into it using the regular
// interfaces).
pub fn save_new_service(
    storage: &mut dyn Storage,
    service_name: &ServiceName,
    service: Service,
) -> Result<Service, ContractError> {
    SERVICES
        .update(storage, service_name, |s| match s {
            None => Ok(service),
            _ => Err(ContractError::ServiceAlreadyExists),
        })
        .map_err(|x| report!(x))
}
