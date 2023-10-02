use axelar_wasm_std_derive::IntoContractError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error("batch contains duplicate message ids")]
    DuplicateMessageIds,

    #[error("could not store outgoing message")]
    StoreOutgoingMessage,

    #[error("could not load outgoing message")]
    LoadOutgoingMessage,

    #[error("could not query the verifier contract")]
    QueryVerifier,

    #[error("could not create the execute message to start verification")]
    CreateVerifierExecuteMsg,

    #[error("could not create the execute message to start routing")]
    CreateRouterExecuteMsg,
}
