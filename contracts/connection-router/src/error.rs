use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("DomainAlreadyExists")]
    DomainAlreadyExists {},

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

    #[error("Semver parsing error: {0}")]
    SemVer(String),

    #[error("DomainFrozen")]
    DomainFrozen { domain: String },

    #[error("GatewayFrozen")]
    GatewayFrozen {},
}

impl From<semver::Error> for ContractError {
    fn from(err: semver::Error) -> Self {
        Self::SemVer(err.to_string())
    }
}
