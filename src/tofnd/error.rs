use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("grpc_filed")]
    Grpc,
    #[error("keygen_filed")]
    KeygenFailed,
    #[error("sign_filed")]
    SignFailed,
}

#[derive(Error, Debug)]
pub enum TofndError {
    #[error("{0}")]
    ExecutionFailed(String),
}
