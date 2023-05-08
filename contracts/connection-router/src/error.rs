use cosmwasm_std::StdError;
use thiserror::Error;

use crate::types::DomainName;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Caller is not authorized")]
    Unauthorized {},

    #[error("Domain already exists")]
    DomainAlreadyExists {},

    #[error("Domain name is invalid")]
    InvalidDomainName {},

    #[error("Message ID is invalid")]
    InvalidMessageID {},

    #[error("Domain was not found")]
    DomainNotFound {},

    #[error("Gateway is not registered")]
    GatewayNotRegistered {},

    #[error("Gateway was already registered")]
    GatewayAlreadyRegistered {},

    #[error("Message was already routed")]
    MessageAlreadyRouted { id: String },

    #[error("Message was not found")]
    MessageNotFound {},

    #[error("Domain is frozen")]
    DomainFrozen { domain: DomainName },

    #[error("Gateway is frozen")]
    GatewayFrozen {},

    #[error("Address is invalid")]
    InvalidAddress {},
}
