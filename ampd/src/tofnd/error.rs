use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("grpc failed")]
    Grpc,
    #[error("keygen failed")]
    KeygenFailed,
    #[error("sign failed")]
    SignFailed,
    #[error(transparent)]
    FromHex(#[from] hex::FromHexError),
    #[error("parsing failed")]
    ParsingFailed,
}

#[derive(Error, Debug)]
pub enum TofndError {
    #[error("{0}")]
    ExecutionFailed(String),
}
