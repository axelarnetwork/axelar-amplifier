use thiserror::Error;
use tonic::Code;

#[derive(Error, Debug)]
pub enum GrpcError {
    #[error("invalid argument provided: {0}")]
    InvalidArgument(String),

    #[error("client cannot keep up with the event stream: {0}")]
    DataLoss(String),

    #[error("internal server error: {0}")]
    InternalError(String),

    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("operation failed: {0}")]
    OperationFailed(String),

    #[error("unknown gRPC error: {0}")]
    UnknownGrpcError(String),
}

#[derive(Error, Debug)]
pub enum AppError {
    #[error("failed to convert event")]
    EventConversion,

    #[error("invalid {0} address")]
    InvalidAddress(&'static str),

    #[error("missing event in response")]
    InvalidResponse,

    #[error("query response is not valid json")]
    InvalidJson,

    #[error("invalid contracts response")]
    InvalidContractsResponse,

    #[error("invalid byte array")]
    InvalidByteArray,

    #[error("invalid url")]
    InvalidUrl,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to connect to the grpc endpoint")]
    GrpcConnection(#[from] tonic::transport::Error),

    #[error(transparent)]
    RpcRequestTimeout(#[from] tokio::time::error::Elapsed),

    #[error(transparent)]
    Grpc(#[from] GrpcError),

    #[error(transparent)]
    App(#[from] AppError),
}

impl From<tonic::Status> for Error {
    fn from(status: tonic::Status) -> Self {
        Error::Grpc(GrpcError::from(status))
    }
}

impl From<tonic::Status> for GrpcError {
    /// Panics if the status code is `Code::Ok`, as this represents a successful
    /// operation and should not be converted to an error.
    fn from(status: tonic::Status) -> Self {
        let message = status.message().to_string();
        match status.code() {
            Code::InvalidArgument => GrpcError::InvalidArgument(message),
            Code::DataLoss => GrpcError::DataLoss(message),
            Code::Internal => GrpcError::InternalError(message),
            Code::Unavailable => GrpcError::ServiceUnavailable(message),
            Code::Unknown => GrpcError::OperationFailed(message),
            Code::Ok => panic!("cannot convert successful status (Code::Ok) to GrpcError"),
            _ => GrpcError::UnknownGrpcError(format!("{}: {}", status.code(), message)),
        }
    }
}
