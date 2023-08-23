use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("grpc failed")]
    Grpc,
    #[error("keygen failed")]
    KeygenFailed,
    #[error("sign failed")]
    SignFailed,
    #[error("{0}")]
    FromHex(#[from] hex::FromHexError),
    #[error("parsing failed")]
    ParsingFailed,
    #[error("send failed")]
    SendFailed,
    #[error("receive failed")]
    RecvFailed,
}

#[derive(Error, Debug)]
pub enum TofndError {
    #[error("{0}")]
    ExecutionFailed(String),
}
