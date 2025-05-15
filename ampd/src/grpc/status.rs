use deref_derive::Deref;
use error_stack::Report;
use report::LoggableError;
use tracing::error;
use valuable::Valuable;

use super::reqs;
use crate::{broadcaster_v2, cosmos, event_sub};

pub fn log<Err>(msg: &str) -> impl Fn(&Report<Err>) + '_ {
    move |err| {
        error!(
            component = "grpc",
            err = LoggableError::from(err).as_value(),
            msg
        );
    }
}

pub trait StatusExt {
    fn into_status(self) -> tonic::Status;
}

#[derive(Deref)]
struct Status(tonic::Status);

impl<Err> StatusExt for Err
where
    Err: Into<Status>,
{
    fn into_status(self) -> tonic::Status {
        self.into().0
    }
}

impl<'a, Err> StatusExt for &Report<Err>
where
    Status: From<&'a Err>,
    Err: Send + Sync + 'static,
    Self: 'a,
{
    fn into_status(self) -> tonic::Status {
        self.current_context().into_status()
    }
}

impl<Err> StatusExt for Report<Err>
where
    for<'a> Status: From<&'a Err>,
    Err: Send + Sync + 'static,
{
    fn into_status(self) -> tonic::Status {
        (&self).into_status()
    }
}

impl From<tonic::Status> for Status {
    fn from(status: tonic::Status) -> Self {
        Self(status)
    }
}

impl From<&reqs::Error> for Status {
    fn from(err: &reqs::Error) -> Self {
        match err {
            reqs::Error::EmptyFilter => tonic::Status::invalid_argument("empty filter provided"),
            reqs::Error::InvalidContractAddress(contract) => tonic::Status::invalid_argument(
                format!("invalid contract address \"{contract}\" provided"),
            ),
            reqs::Error::InvalidQuery => tonic::Status::invalid_argument("invalid query provided"),
            reqs::Error::EmptyBroadcastMsg => {
                tonic::Status::invalid_argument("empty broadcast message provided")
            }
        }
        .into()
    }
}

impl From<&event_sub::Error> for Status {
    fn from(err: &event_sub::Error) -> Self {
        match err {
            event_sub::Error::LatestBlockQuery | event_sub::Error::BlockResultsQuery { .. } => {
                tonic::Status::unavailable("blockchain service is temporarily unavailable")
            }
            event_sub::Error::EventDecoding { .. } => {
                tonic::Status::internal("server encountered an error processing blockchain events")
            }
            event_sub::Error::BroadcastStreamRecv(_) => {
                tonic::Status::data_loss("events have been missed due to client lag")
            }
        }
        .into()
    }
}

impl From<&broadcaster_v2::Error> for Status {
    fn from(err: &broadcaster_v2::Error) -> Self {
        match err {
            broadcaster_v2::Error::EstimateGas | broadcaster_v2::Error::GasExceedsGasCap { .. } => {
                tonic::Status::invalid_argument("failed to estimate gas or gas exceeds gas cap")
            }
            broadcaster_v2::Error::AccountQuery | broadcaster_v2::Error::BroadcastTx => {
                tonic::Status::unavailable("blockchain service is temporarily unavailable")
            }
            broadcaster_v2::Error::SignTx => {
                tonic::Status::unavailable("signing service is temporarily unavailable")
            }
            broadcaster_v2::Error::EnqueueMsg
            | broadcaster_v2::Error::FeeAdjustment
            | broadcaster_v2::Error::InvalidPubKey
            | broadcaster_v2::Error::ReceiveTxResult(_) => {
                tonic::Status::internal("server encountered an error processing request")
            }
        }
        .into()
    }
}

impl From<&cosmos::Error> for Status {
    fn from(err: &cosmos::Error) -> Self {
        match err {
            cosmos::Error::GrpcConnection(_) | cosmos::Error::GrpcRequest(_) => {
                tonic::Status::unavailable("blockchain service is temporarily unavailable")
            }
            cosmos::Error::QuerySmartContractState(reason) => tonic::Status::unknown(format!(
                "failed to query smart contract state with error {reason}"
            )),
            cosmos::Error::GasInfoMissing
            | cosmos::Error::AccountMissing
            | cosmos::Error::TxResponseMissing
            | cosmos::Error::MalformedResponse
            | cosmos::Error::TxBuilding => {
                tonic::Status::internal("server encountered an error processing request")
            }
        }
        .into()
    }
}

#[cfg(test)]
mod tests {
    use error_stack::report;
    use tendermint::block::Height;
    use tokio::sync::oneshot;
    use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
    use tonic::Code;

    use super::*;

    #[test]
    fn reqs_errors_to_status() {
        assert_eq!(
            reqs::Error::EmptyFilter.into_status().code(),
            Code::InvalidArgument
        );
        assert_eq!(
            reqs::Error::InvalidContractAddress("invalid_contract_address".to_string())
                .into_status()
                .code(),
            Code::InvalidArgument
        );
        assert_eq!(
            reqs::Error::InvalidQuery.into_status().code(),
            Code::InvalidArgument
        );
        assert_eq!(
            reqs::Error::EmptyBroadcastMsg.into_status().code(),
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
            report!(event_sub::Error::BlockResultsQuery {
                block: Height::default()
            })
            .into_status()
            .code(),
            Code::Unavailable
        );
        assert_eq!(
            (&report!(event_sub::Error::EventDecoding {
                block: Height::default()
            }))
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

    #[tokio::test]
    async fn broadcaster_v2_errors_to_status() {
        assert_eq!(
            broadcaster_v2::Error::EstimateGas.into_status().code(),
            Code::InvalidArgument
        );
        assert_eq!(
            broadcaster_v2::Error::GasExceedsGasCap {
                msg_type: "test_message".to_string(),
                gas: 1000000,
                gas_cap: 500000
            }
            .into_status()
            .code(),
            Code::InvalidArgument
        );
        assert_eq!(
            broadcaster_v2::Error::AccountQuery.into_status().code(),
            Code::Unavailable
        );
        assert_eq!(
            broadcaster_v2::Error::BroadcastTx.into_status().code(),
            Code::Unavailable
        );
        assert_eq!(
            broadcaster_v2::Error::SignTx.into_status().code(),
            Code::Unavailable
        );
        assert_eq!(
            broadcaster_v2::Error::EnqueueMsg.into_status().code(),
            Code::Internal
        );
        assert_eq!(
            broadcaster_v2::Error::FeeAdjustment.into_status().code(),
            Code::Internal
        );
        assert_eq!(
            broadcaster_v2::Error::InvalidPubKey.into_status().code(),
            Code::Internal
        );
        let (_, rx) = oneshot::channel::<u32>();
        assert_eq!(
            broadcaster_v2::Error::ReceiveTxResult(rx.await.unwrap_err())
                .into_status()
                .code(),
            Code::Internal
        );
    }

    #[test]
    fn cosmos_errors_to_status() {
        assert_eq!(
            cosmos::Error::GrpcRequest(tonic::Status::unavailable("service unavailable"))
                .into_status()
                .code(),
            Code::Unavailable
        );
        assert_eq!(
            cosmos::Error::QuerySmartContractState("contract execution error".to_string())
                .into_status()
                .code(),
            Code::Unknown
        );
        assert_eq!(
            cosmos::Error::GasInfoMissing.into_status().code(),
            Code::Internal
        );
        assert_eq!(
            cosmos::Error::AccountMissing.into_status().code(),
            Code::Internal
        );
        assert_eq!(
            cosmos::Error::TxResponseMissing.into_status().code(),
            Code::Internal
        );
        assert_eq!(
            cosmos::Error::MalformedResponse.into_status().code(),
            Code::Internal
        );
        assert_eq!(
            cosmos::Error::TxBuilding.into_status().code(),
            Code::Internal
        );
    }
}
