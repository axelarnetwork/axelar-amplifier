use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GatewayError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unexpected tokens received")]
    TokenReceived {},
    #[error("{msg}")]
    AxelarGatewayError { msg: String },
}
