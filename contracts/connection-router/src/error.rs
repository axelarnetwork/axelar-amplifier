use cosmwasm_std::StdError;
use thiserror::Error;

use crate::state::DomainName;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("DomainAlreadyExists")]
    DomainAlreadyExists {},

    #[error("InvalidDomainName")]
    InvalidDomainName {},

    #[error("InvalidMessageID")]
    InvalidMessageID {},

    #[error("DomainNotFound")]
    DomainNotFound {},

    #[error("GatewayNotRegistered")]
    GatewayNotRegistered {},

    #[error("GatewayAlreadyRegistered")]
    GatewayAlreadyRegistered {},

    #[error("MessageHashMistmatch")]
    MessageHashMismatch {},

    #[error("MessageAlreadyRouted")]
    MessageAlreadyRouted { id: String },

    #[error("MessageNotFound")]
    MessageNotFound {},

    #[error("DomainFrozen")]
    DomainFrozen { domain: DomainName },

    #[error("GatewayFrozen")]
    GatewayFrozen {},
}
