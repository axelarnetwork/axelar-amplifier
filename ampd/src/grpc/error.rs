use error_stack::Report;
use tonic::Status;

use super::event_filters;
use crate::event_sub;

pub trait ErrorExt {
    fn into_status(self) -> Status;
}

struct Error(Status);

impl<Err> ErrorExt for Err
where
    Err: Into<Error>,
{
    fn into_status(self) -> Status {
        self.into().0
    }
}

impl<'a, Err> ErrorExt for &Report<Err>
where
    Error: From<&'a Err>,
    Err: Send + Sync + 'static,
    Self: 'a,
{
    fn into_status(self) -> Status {
        self.current_context().into_status()
    }
}

impl<Err> ErrorExt for Report<Err>
where
    for<'a> Error: From<&'a Err>,
    Err: Send + Sync + 'static,
{
    fn into_status(self) -> Status {
        (&self).into_status()
    }
}

impl From<Status> for Error {
    fn from(status: Status) -> Self {
        Self(status)
    }
}

impl From<&event_filters::Error> for Error {
    fn from(err: &event_filters::Error) -> Self {
        match err {
            event_filters::Error::EmptyFilter => Status::invalid_argument("empty filter provided"),
            event_filters::Error::InvalidContractAddress(contract) => Status::invalid_argument(
                format!("invalid contract address {} provided in filters", contract),
            ),
        }
        .into()
    }
}

impl From<&event_sub::Error> for Error {
    fn from(err: &event_sub::Error) -> Self {
        match err {
            event_sub::Error::LatestBlockQuery | event_sub::Error::BlockResultsQuery { .. } => {
                Status::unavailable("blockchain service is temporarily unavailable")
            }
            event_sub::Error::EventDecoding { .. } => {
                Status::internal("server encountered an error processing blockchain events")
            }
            event_sub::Error::BroadcastStreamRecv(_) => {
                Status::data_loss("events have been missed due to client lag")
            }
        }
        .into()
    }
}

#[cfg(test)]
mod tests {
    use tendermint::block::Height;
    use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
    use tonic::Code;

    use super::*;

    #[test]
    fn event_filters_errors_to_status() {
        assert_eq!(
            event_filters::Error::EmptyFilter.into_status().code(),
            Code::InvalidArgument
        );
        assert_eq!(
            event_filters::Error::InvalidContractAddress("invalid_contract_address".to_string())
                .into_status()
                .code(),
            Code::InvalidArgument
        );
    }

    #[test]
    fn event_sub_errors_to_status() {
        assert_eq!(
            event_sub::Error::LatestBlockQuery.into_status().code(),
            Code::Unavailable
        );
        assert_eq!(
            event_sub::Error::BlockResultsQuery {
                block: Height::default()
            }
            .into_status()
            .code(),
            Code::Unavailable
        );
        assert_eq!(
            event_sub::Error::EventDecoding {
                block: Height::default()
            }
            .into_status()
            .code(),
            Code::Internal
        );
        assert_eq!(
            event_sub::Error::BroadcastStreamRecv(BroadcastStreamRecvError::Lagged(10))
                .into_status()
                .code(),
            Code::DataLoss
        );
    }
}
