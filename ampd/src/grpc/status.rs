use deref_derive::Deref;
use error_stack::Report;
use report::LoggableError;
use tracing::error;
use valuable::Valuable;

use super::reqs;
use crate::{broadcaster_v2, cosmos, event_sub, tofnd};

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

impl<T> StatusExt for T
where
    T: Into<Status>,
{
    fn into_status(self) -> tonic::Status {
        self.into().0
    }
}

impl<'a, Err> From<&'a Report<Err>> for Status
where
    Status: From<&'a Err>,
    Err: Send + Sync + 'static,
{
    fn from(err: &'a Report<Err>) -> Self {
        err.current_context().into()
    }
}

impl<Err> From<Report<Err>> for Status
where
    for<'a> Status: From<&'a Err>,
    Err: Send + Sync + 'static,
{
    fn from(err: Report<Err>) -> Self {
        (&err).into()
    }
}

impl From<tonic::Status> for Status {
    fn from(status: tonic::Status) -> Self {
        Self(status)
    }
}

impl From<&reqs::Error> for Status {
    fn from(err: &reqs::Error) -> Self {
        tonic::Status::invalid_argument(err.to_string()).into()
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
                tonic::Status::invalid_argument(err.to_string())
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
            | broadcaster_v2::Error::ReceiveTxResult(_)
            | broadcaster_v2::Error::ConfirmTx(_)
            | broadcaster_v2::Error::BalanceQuery
            | broadcaster_v2::Error::InsufficientBalance { .. } => {
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
            cosmos::Error::QueryContractState(_) => tonic::Status::unknown(err.to_string()),
            cosmos::Error::GasInfoMissing
            | cosmos::Error::AccountMissing
            | cosmos::Error::TxResponseMissing
            | cosmos::Error::BalanceMissing
            | cosmos::Error::MalformedResponse
            | cosmos::Error::TxBuilding => {
                tonic::Status::internal("server encountered an error processing request")
            }
        }
        .into()
    }
}

impl From<&tofnd::Error> for Status {
    fn from(err: &tofnd::Error) -> Self {
        match err {
            tofnd::Error::GrpcConnection(_) => {
                tonic::Status::unavailable("crypto service is temporarily unavailable")
            }
            tofnd::Error::GrpcRequest(status) => status.clone(), // passing status through because we control tofnd
            tofnd::Error::InvalidKeygenResponse
            | tofnd::Error::InvalidSignResponse
            | tofnd::Error::ExecutionFailed(_) => {
                tonic::Status::internal("server encountered an error processing request")
            }
        }
        .into()
    }
}

#[cfg(test)]
mod tests {
    use tendermint::block::Height;
    use tokio::sync::oneshot;
    use tokio_stream::wrappers::errors::BroadcastStreamRecvError;

    use super::*;

    #[test]
    fn reqs_errors_to_status() {
        let empty_filter = reqs::Error::EmptyFilter;
        let invalid_contract_address =
            reqs::Error::InvalidContractAddress("invalid_contract_address".to_string());
        let invalid_query = reqs::Error::InvalidQuery;
        let empty_broadcast_msg = reqs::Error::EmptyBroadcastMsg;

        goldie::assert_debug!(vec![
            (empty_filter.into_status().code(), empty_filter),
            (
                invalid_contract_address.into_status().code(),
                invalid_contract_address
            ),
            (invalid_query.into_status().code(), invalid_query),
            (
                empty_broadcast_msg.into_status().code(),
                empty_broadcast_msg
            ),
        ]);
    }

    #[test]
    fn event_sub_errors_to_status() {
        let latest_block_query = event_sub::Error::LatestBlockQuery;
        let block_results_query = event_sub::Error::BlockResultsQuery {
            block: Height::default(),
        };
        let event_decoding = event_sub::Error::EventDecoding {
            block: Height::default(),
        };
        let broadcast_stream_recv =
            event_sub::Error::BroadcastStreamRecv(BroadcastStreamRecvError::Lagged(10));

        goldie::assert_debug!(vec![
            (latest_block_query.into_status().code(), latest_block_query),
            (
                block_results_query.into_status().code(),
                block_results_query
            ),
            (event_decoding.into_status().code(), event_decoding),
            (
                broadcast_stream_recv.into_status().code(),
                broadcast_stream_recv
            ),
        ]);
    }

    #[tokio::test]
    async fn broadcaster_v2_errors_to_status() {
        let estimate_gas = broadcaster_v2::Error::EstimateGas;
        let gas_exceeds_gas_cap = broadcaster_v2::Error::GasExceedsGasCap {
            msg_type: "test_message".to_string(),
            gas: 1000000,
            gas_cap: 500000,
        };
        let account_query = broadcaster_v2::Error::AccountQuery;
        let broadcast_tx = broadcaster_v2::Error::BroadcastTx;
        let sign_tx = broadcaster_v2::Error::SignTx;
        let enqueue_msg = broadcaster_v2::Error::EnqueueMsg;
        let fee_adjustment = broadcaster_v2::Error::FeeAdjustment;
        let invalid_pub_key = broadcaster_v2::Error::InvalidPubKey;
        let (_, rx) = oneshot::channel::<u32>();
        let receive_tx_result = broadcaster_v2::Error::ReceiveTxResult(rx.await.unwrap_err());

        goldie::assert_debug!(vec![
            (estimate_gas.into_status().code(), estimate_gas),
            (
                gas_exceeds_gas_cap.into_status().code(),
                gas_exceeds_gas_cap
            ),
            (account_query.into_status().code(), account_query),
            (broadcast_tx.into_status().code(), broadcast_tx),
            (sign_tx.into_status().code(), sign_tx),
            (enqueue_msg.into_status().code(), enqueue_msg),
            (fee_adjustment.into_status().code(), fee_adjustment),
            (invalid_pub_key.into_status().code(), invalid_pub_key),
            (receive_tx_result.into_status().code(), receive_tx_result),
        ]);
    }

    #[test]
    fn cosmos_errors_to_status() {
        let grpc_request =
            cosmos::Error::GrpcRequest(tonic::Status::unavailable("service unavailable"));
        let query_contract_state =
            cosmos::Error::QueryContractState("contract execution error".to_string());
        let gas_info_missing = cosmos::Error::GasInfoMissing;
        let account_missing = cosmos::Error::AccountMissing;
        let tx_response_missing = cosmos::Error::TxResponseMissing;
        let malformed_response = cosmos::Error::MalformedResponse;
        let tx_building = cosmos::Error::TxBuilding;

        goldie::assert_debug!(vec![
            (grpc_request.into_status().code(), grpc_request),
            (
                query_contract_state.into_status().code(),
                query_contract_state
            ),
            (gas_info_missing.into_status().code(), gas_info_missing),
            (account_missing.into_status().code(), account_missing),
            (
                tx_response_missing.into_status().code(),
                tx_response_missing
            ),
            (malformed_response.into_status().code(), malformed_response),
            (tx_building.into_status().code(), tx_building),
        ]);
    }

    #[test]
    fn tofnd_errors_to_status() {
        let grpc_request =
            tofnd::Error::GrpcRequest(tonic::Status::permission_denied("permission denied"));
        let invalid_keygen_response = tofnd::Error::InvalidKeygenResponse;
        let invalid_sign_response = tofnd::Error::InvalidSignResponse;
        let execution_failed = tofnd::Error::ExecutionFailed("key generation failed".to_string());

        goldie::assert_debug!(vec![
            (grpc_request.into_status().code(), grpc_request),
            (
                invalid_keygen_response.into_status().code(),
                invalid_keygen_response
            ),
            (
                invalid_sign_response.into_status().code(),
                invalid_sign_response
            ),
            (execution_failed.into_status().code(), execution_failed),
        ]);
    }
}
