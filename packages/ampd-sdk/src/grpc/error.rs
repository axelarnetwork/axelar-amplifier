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
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to connect to the grpc endpoint")]
    GrpcConnection(#[from] tonic::transport::Error),

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
    fn from(status: tonic::Status) -> Self {
        let message = status.message().to_string();
        match status.code() {
            Code::InvalidArgument => GrpcError::InvalidArgument(message),
            Code::DataLoss => GrpcError::DataLoss(message),
            Code::Internal => GrpcError::InternalError(message),
            Code::Unavailable => GrpcError::ServiceUnavailable(message),
            Code::Unknown => GrpcError::OperationFailed(message),
            _ => GrpcError::UnknownGrpcError(format!("{}: {}", status.code(), message)),
        }
    }
}

impl GrpcError {
    pub fn grpc_code(&self) -> Code {
        match self {
            GrpcError::InvalidArgument(_) => Code::InvalidArgument,
            GrpcError::DataLoss(_) => Code::DataLoss,
            GrpcError::InternalError(_) => Code::Internal,
            GrpcError::ServiceUnavailable(_) => Code::Unavailable,
            GrpcError::OperationFailed(_) => Code::Unknown,
            GrpcError::UnknownGrpcError(_) => Code::Unknown,
        }
    }
}

impl Error {
    pub fn grpc_code(&self) -> Option<Code> {
        match self {
            Error::Grpc(grpc_err) => Some(grpc_err.grpc_code()),
            _ => None,
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Error::Grpc(
                GrpcError::DataLoss(_)
                    | GrpcError::ServiceUnavailable(_)
                    | GrpcError::InternalError(_),
            )
        )
    }

    pub fn is_client_error(&self) -> bool {
        matches!(
            self,
            Error::Grpc(GrpcError::InvalidArgument(_))
                | Error::App(
                    AppError::InvalidAddress(_)
                        | AppError::InvalidJson
                        | AppError::InvalidByteArray,
                )
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_conversion() {
        let status = tonic::Status::invalid_argument("Invalid filter");
        let error = Error::from(status);
        assert!(matches!(error, Error::Grpc(GrpcError::InvalidArgument(_))));
        assert!(error.is_client_error());
        assert!(!error.is_retryable());
    }

    #[test]
    fn test_grpc_code_mapping() {
        let error = Error::Grpc(GrpcError::InvalidArgument("test".to_string()));
        assert_eq!(error.grpc_code(), Some(Code::InvalidArgument));

        let error = Error::Grpc(GrpcError::DataLoss("test".to_string()));
        assert_eq!(error.grpc_code(), Some(Code::DataLoss));

        let error = Error::App(AppError::InvalidJson);
        assert_eq!(error.grpc_code(), None);
    }

    #[test]
    fn test_error_categorization() {
        assert!(Error::Grpc(GrpcError::DataLoss("test".to_string())).is_retryable());
        assert!(Error::Grpc(GrpcError::ServiceUnavailable("test".to_string())).is_retryable());
        assert!(!Error::Grpc(GrpcError::InvalidArgument("test".to_string())).is_retryable());

        assert!(Error::Grpc(GrpcError::InvalidArgument("test".to_string())).is_client_error());
        assert!(Error::App(AppError::InvalidJson).is_client_error());
        assert!(!Error::Grpc(GrpcError::InternalError("test".to_string())).is_client_error());
    }
}
