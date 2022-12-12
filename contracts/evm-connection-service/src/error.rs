use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},
    #[error("Action already requested")]
    ActionAlreadyRequested {},
    #[error("Invalid request id")]
    InvalidRequestId {},
    #[error("Voting already closed")]
    VotingAlreadyClosed {},
}
