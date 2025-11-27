use cosmwasm_std::Storage;
use cw_storage_plus::Map;
use error_stack::{report, Result};
use service_registry_api::error::ContractError;
use service_registry_api::Service;

type ServiceName = String;

pub const SERVICES: Map<&ServiceName, Service> = Map::new("services");

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