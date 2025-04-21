use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to connect to the grpc endpoint")]
    GrpcConnection(#[from] tonic::transport::Error),
    #[error("failed to make the grpc request")]
    GrpcRequest(#[from] tonic::Status),
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
