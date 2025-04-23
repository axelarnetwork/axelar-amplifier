use std::time::Duration;

use async_trait::async_trait;
use cosmrs::proto::cosmos::auth::v1beta1::query_client::QueryClient as AuthQueryClient;
use cosmrs::proto::cosmos::auth::v1beta1::{QueryAccountRequest, QueryAccountResponse};
use cosmrs::proto::cosmos::bank::v1beta1::query_client::QueryClient as BankQueryClient;
use cosmrs::proto::cosmos::bank::v1beta1::{QueryBalanceRequest, QueryBalanceResponse};
use cosmrs::proto::cosmos::tx::v1beta1::service_client::ServiceClient;
use cosmrs::proto::cosmos::tx::v1beta1::{
    BroadcastTxRequest, BroadcastTxResponse, GetTxRequest, GetTxResponse, SimulateRequest,
    SimulateResponse,
};
use mockall::automock;
use report::ErrorExt;
use thiserror::Error;
use tonic::transport::Channel;
use tonic::Response;

type Result<T> = error_stack::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to connect to the grpc endpoint")]
    GrpcConnection(#[from] tonic::transport::Error),
    #[error("failed to make the grpc request")]
    GrpcRequest(#[from] tonic::Status),
}

#[automock]
#[async_trait]
pub trait CosmosClient {
    async fn broadcast_tx(&mut self, req: BroadcastTxRequest) -> Result<BroadcastTxResponse>;
    async fn simulate(&mut self, req: SimulateRequest) -> Result<SimulateResponse>;
    async fn tx(&mut self, req: GetTxRequest) -> Result<GetTxResponse>;

    async fn account(&mut self, address: QueryAccountRequest) -> Result<QueryAccountResponse>;

    async fn balance(&mut self, request: QueryBalanceRequest) -> Result<QueryBalanceResponse>;
}

/// CosmosGrpcClient implements the CosmosClient trait to interact with Cosmos blockchain nodes via gRPC.
///
/// # Clone Implementation
///
/// This struct derives the `Clone` trait, which enables creating copies of the client instance.
/// When `clone()` is called on a CosmosGrpcClient:
///
/// - A new CosmosGrpcClient instance is created with cloned fields
/// - The underlying gRPC clients (auth, bank, service) are cloned
/// - The tonic::transport::Channel is cloned, but this doesn't create a new TCP connection
///   Instead, it creates a new reference to the same underlying connection pool
///
/// This cloning approach is efficient for concurrent operations since it allows multiple
/// client instances to share the same connection resources while maintaining independent state.
///
#[derive(Clone)]
pub struct CosmosGrpcClient {
    auth: AuthQueryClient<Channel>,
    bank: BankQueryClient<Channel>,
    service: ServiceClient<Channel>,
}

impl CosmosGrpcClient {
    pub async fn new(url: &str, timeout: Duration) -> Result<Self> {
        let endpoint: tonic::transport::Endpoint = url.parse().map_err(ErrorExt::into_report)?;
        let conn = endpoint
            .timeout(timeout)
            .connect_timeout(timeout)
            .connect()
            .await
            .map_err(ErrorExt::into_report)?;

        Ok(Self {
            auth: AuthQueryClient::new(conn.clone()),
            bank: BankQueryClient::new(conn.clone()),
            service: ServiceClient::new(conn),
        })
    }
}

#[async_trait]
impl CosmosClient for CosmosGrpcClient {
    async fn broadcast_tx(&mut self, request: BroadcastTxRequest) -> Result<BroadcastTxResponse> {
        self.service
            .broadcast_tx(request)
            .await
            .map(Response::into_inner)
            .map_err(ErrorExt::into_report)
    }

    async fn simulate(&mut self, req: SimulateRequest) -> Result<SimulateResponse> {
        self.service
            .simulate(req)
            .await
            .map(Response::into_inner)
            .map_err(ErrorExt::into_report)
    }

    async fn tx(&mut self, req: GetTxRequest) -> Result<GetTxResponse> {
        self.service
            .get_tx(req)
            .await
            .map(Response::into_inner)
            .map_err(ErrorExt::into_report)
    }

    async fn account(&mut self, request: QueryAccountRequest) -> Result<QueryAccountResponse> {
        self.auth
            .account(request)
            .await
            .map(Response::into_inner)
            .map_err(ErrorExt::into_report)
    }

    async fn balance(&mut self, request: QueryBalanceRequest) -> Result<QueryBalanceResponse> {
        self.bank
            .balance(request)
            .await
            .map(Response::into_inner)
            .map_err(ErrorExt::into_report)
    }
}

#[cfg(test)]
mod tests {
    use cosmrs::proto::cosmos::auth::v1beta1::BaseAccount;
    use cosmrs::proto::cosmos::base::abci::v1beta1::{
        AbciMessageLog, Attribute, GasInfo, Result as AbciResult, StringEvent, TxResponse,
    };
    use cosmrs::proto::cosmos::base::v1beta1::Coin;
    use cosmrs::proto::cosmos::tx::v1beta1::{BroadcastMode, Tx};
    use cosmrs::tendermint::abci;
    use cosmrs::tx::MessageExt;
    use cosmrs::Any;
    use serde_json::json;

    use super::*;

    #[test]
    fn ensure_broadcast_tx_req_res_serialization_do_not_change() {
        let req = BroadcastTxRequest {
            tx_bytes: vec![1, 2, 3, 4, 5],
            mode: BroadcastMode::Sync as i32,
        };
        let res = BroadcastTxResponse {
            tx_response: Some(TxResponse {
                height: 100,
                txhash: "txhash".to_string(),
                codespace: "codespace".to_string(),
                code: 10,
                data: "data".to_string(),
                raw_log: "raw_log".to_string(),
                logs: vec![AbciMessageLog {
                    msg_index: 0,
                    log: "log".to_string(),
                    events: vec![StringEvent {
                        r#type: "event_type".to_string(),
                        attributes: vec![Attribute {
                            key: "key".to_string(),
                            value: "value".to_string(),
                        }],
                    }],
                }],
                info: "info".to_string(),
                gas_wanted: 1000,
                gas_used: 900,
                tx: Some(prost_types::Any {
                    type_url: "axelar.type".to_string(),
                    value: vec![1, 2, 3, 4, 5, 6],
                }),
                timestamp: "timestamp".to_string(),
                events: vec![abci::Event {
                    kind: "event_type".to_string(),
                    attributes: vec![abci::EventAttribute {
                        index: true,
                        key: "key".to_string(),
                        value: "value".to_string(),
                    }],
                }
                .into()],
            }),
        };

        goldie::assert_json!(json!({
            "req": format!("{:?}", req),
            "res": format!("{:?}", res),
            "req_bytes": req.to_bytes().unwrap(),
            "res_bytes": res.to_bytes().unwrap()
        }));
    }

    #[test]
    fn ensure_simulate_req_res_serialization_do_not_change() {
        let req = SimulateRequest {
            #[allow(deprecated)]
            tx: Some(Tx {
                body: None,
                auth_info: None,
                signatures: vec![vec![5, 6, 7, 8]],
            }),
            tx_bytes: vec![1, 2, 3, 4, 5],
        };
        let res = SimulateResponse {
            gas_info: Some(GasInfo {
                gas_wanted: 1000,
                gas_used: 900,
            }),
            result: Some(AbciResult {
                #[allow(deprecated)]
                data: vec![1, 2, 3],
                log: "simulation log".to_string(),
                events: vec![abci::Event {
                    kind: "simulation_event".to_string(),
                    attributes: vec![abci::EventAttribute {
                        index: true,
                        key: "sim_key".to_string(),
                        value: "sim_value".to_string(),
                    }],
                }
                .into()],
                msg_responses: vec![prost_types::Any {
                    type_url: "/cosmos.base.v1beta1.MsgResponse".to_string(),
                    value: vec![1, 2, 3, 4, 5],
                }],
            }),
        };

        goldie::assert_json!(json!({
            "req": format!("{:?}", req),
            "res": format!("{:?}", res),
            "req_bytes": req.to_bytes().unwrap(),
            "res_bytes": res.to_bytes().unwrap()
        }));
    }

    #[test]
    fn ensure_get_tx_req_res_serialization_do_not_change() {
        let req = GetTxRequest {
            hash: "0123456789ABCDEF".to_string(),
        };
        let res = GetTxResponse {
            tx: Some(Tx {
                body: None,
                auth_info: None,
                signatures: vec![vec![1, 2, 3, 4]],
            }),
            tx_response: Some(TxResponse {
                height: 100,
                txhash: "0123456789ABCDEF".to_string(),
                codespace: "codespace".to_string(),
                code: 0,
                data: "data".to_string(),
                raw_log: "[{\"events\":[{\"type\":\"tx_event\",\"attributes\":[{\"key\":\"action\",\"value\":\"get_tx\"}]}]}]".to_string(),
                logs: vec![AbciMessageLog {
                    msg_index: 0,
                    log: "tx log message".to_string(),
                    events: vec![StringEvent {
                        r#type: "tx_get_event".to_string(),
                        attributes: vec![Attribute {
                            key: "tx_key".to_string(),
                            value: "tx_value".to_string(),
                        }],
                    }],
                }],
                info: "info".to_string(),
                gas_wanted: 1000,
                gas_used: 900,
                tx: Some(prost_types::Any {
                    type_url: "/cosmos.tx.v1beta1.Tx".to_string(),
                    value: vec![10, 20, 30, 40, 50],
                }),
                timestamp: "2025-04-23T17:00:00Z".to_string(),
                events: vec![abci::Event {
                    kind: "tx_result_event".to_string(),
                    attributes: vec![abci::EventAttribute {
                        index: true,
                        key: "tx_result_key".to_string(),
                        value: "tx_result_value".to_string(),
                    }],
                }.into()],
            }),
        };

        goldie::assert_json!(json!({
            "req": format!("{:?}", req),
            "res": format!("{:?}", res),
            "req_bytes": req.to_bytes().unwrap(),
            "res_bytes": res.to_bytes().unwrap()
        }));
    }

    #[test]
    fn ensure_account_req_res_serialization_do_not_change() {
        let req = QueryAccountRequest {
            address: "axelar1q95p9fntvqn6jm9m0u5092pu9ulq3chn0zkuks".to_string(),
        };
        let base_account = BaseAccount {
            address: "axelar1q95p9fntvqn6jm9m0u5092pu9ulq3chn0zkuks".to_string(),
            pub_key: Some(prost_types::Any {
                type_url: "/cosmos.crypto.secp256k1.PubKey".to_string(),
                value: vec![
                    10, 33, 2, 136, 177, 245, 49, 184, 120, 113, 219, 192, 55, 41, 81,
                ],
            }),
            account_number: 42,
            sequence: 7,
        };
        let res = QueryAccountResponse {
            account: Some(Any {
                type_url: "/cosmos.auth.v1beta1.BaseAccount".to_string(),
                value: base_account.to_bytes().unwrap(),
            }),
        };

        goldie::assert_json!(json!({
            "req": format!("{:?}", req),
            "res": format!("{:?}", res),
            "req_bytes": req.to_bytes().unwrap(),
            "res_bytes": res.to_bytes().unwrap()
        }));
    }

    #[test]
    fn ensure_balance_req_res_serialization_do_not_change() {
        let req = QueryBalanceRequest {
            address: "axelar1q95p9fntvqn6jm9m0u5092pu9ulq3chn0zkuks".to_string(),
            denom: "uaxl".to_string(),
        };
        let res = QueryBalanceResponse {
            balance: Some(Coin {
                denom: "uaxl".to_string(),
                amount: "1000000".to_string(),
            }),
        };

        goldie::assert_json!(json!({
            "req": format!("{:?}", req),
            "res": format!("{:?}", res),
            "req_bytes": req.to_bytes().unwrap(),
            "res_bytes": res.to_bytes().unwrap()
        }));
    }
}
