use report::ResultExt;
use thiserror::Error;
use tonic::Code;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to connect to the grpc endpoint")]
    GrpcConnection(#[from] tonic::transport::Error),

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

impl From<tonic::Status> for Error {
    fn from(status: tonic::Status) -> Self {
        let message = status.message().to_string();
        match status.code() {
            Code::InvalidArgument => Error::InvalidArgument(message),
            Code::DataLoss => Error::DataLoss(message),
            Code::Internal => Error::InternalError(message),
            Code::Unavailable => Error::ServiceUnavailable(message),
            Code::Unknown => Error::OperationFailed(message),
            _ => Error::UnknownGrpcError(format!("{}: {}", status.code(), message)),
        }
    }
}

impl Error {
    pub fn grpc_code(&self) -> Option<Code> {
        match self {
            Error::InvalidArgument(_) => Some(Code::InvalidArgument),
            Error::DataLoss(_) => Some(Code::DataLoss),
            Error::InternalError(_) => Some(Code::Internal),
            Error::ServiceUnavailable(_) => Some(Code::Unavailable),
            Error::OperationFailed(_) => Some(Code::Unknown),
            _ => None,
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Error::DataLoss(_) | Error::ServiceUnavailable(_) | Error::InternalError(_)
        )
    }

    pub fn is_client_error(&self) -> bool {
        matches!(
            self,
            Error::InvalidArgument(_)
                | Error::InvalidAddress(_)
                | Error::InvalidJson
                | Error::InvalidByteArray
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
        assert!(matches!(error, Error::InvalidArgument(_)));
        assert!(error.is_client_error());
        assert!(!error.is_retryable());
    }

    #[test]
    fn test_grpc_code_mapping() {
        let error = Error::InvalidArgument("test_error".to_string());
        assert_eq!(error.grpc_code(), Some(Code::InvalidArgument));

        let error = Error::DataLoss("test_error".to_string());
        assert_eq!(error.grpc_code(), Some(Code::DataLoss));
    }

    #[test]
    fn test_error_categorization() {
        assert!(Error::DataLoss("test".to_string()).is_retryable());
        assert!(Error::ServiceUnavailable("test_error".to_string()).is_retryable());
        assert!(!Error::InvalidArgument("test_error".to_string()).is_retryable());

        assert!(Error::InvalidArgument("test_error".to_string()).is_client_error());
        assert!(Error::InvalidJson.is_client_error());
        assert!(!Error::InternalError("test_error".to_string()).is_client_error());
    }
}
