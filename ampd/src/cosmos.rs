use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use ::std::fmt::Debug;
use async_trait::async_trait;
use cosmrs::proto::cosmos::auth::v1beta1::query_client::QueryClient as AuthQueryClient;
use cosmrs::proto::cosmos::auth::v1beta1::{
    BaseAccount, QueryAccountRequest, QueryAccountResponse,
};
use cosmrs::proto::cosmos::bank::v1beta1::query_client::QueryClient as BankQueryClient;
use cosmrs::proto::cosmos::bank::v1beta1::{QueryBalanceRequest, QueryBalanceResponse};
use cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse;
use cosmrs::proto::cosmos::tx::v1beta1::service_client::ServiceClient;
use cosmrs::proto::cosmos::tx::v1beta1::{
    BroadcastMode, BroadcastTxRequest, BroadcastTxResponse, GetTxRequest, GetTxResponse,
    SimulateRequest, SimulateResponse, TxRaw,
};
use cosmrs::proto::cosmwasm::wasm::v1::query_client::QueryClient as CosmWasmQueryClient;
use cosmrs::proto::cosmwasm::wasm::v1::{
    QuerySmartContractStateRequest, QuerySmartContractStateResponse,
};
use cosmrs::tx::MessageExt;
use cosmrs::{Any, Coin, Denom, Gas};
use error_stack::{report, ResultExt};
use mockall::mock;
use prost::Message;
use report::{ErrorExt, ResultCompatExt};
use thiserror::Error;
use tonic::transport::Channel;
use tonic::{Code, Response, Status};

use crate::broadcast::Tx;
use crate::types::debug::REDACTED_VALUE;
use crate::types::{CosmosPublicKey, TMAddress};

type Result<T> = error_stack::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    GrpcConnection(#[from] tonic::transport::Error),
    #[error(transparent)]
    GrpcRequest(#[from] Status),
    #[error("gas info is missing in the query response")]
    GasInfoMissing,
    #[error("account is missing in the query response")]
    AccountMissing,
    #[error("tx response is missing in the broadcast tx response")]
    TxResponseMissing,
    #[error("account balance is missing in the query response")]
    BalanceMissing,
    #[error("failed to decode the query response")]
    MalformedResponse,
    #[error("failed to build tx")]
    TxBuilding,
    #[error("failed to query the contract state with error {0}")]
    QueryContractState(String),
}

mock! {
    #[derive(Debug)]
    pub CosmosClient{}

    impl Clone for CosmosClient {
        fn clone(&self) -> Self;
    }


    #[async_trait]
    impl CosmosClient for CosmosClient {
        async fn broadcast_tx(&mut self, req: BroadcastTxRequest) -> Result<BroadcastTxResponse>;
        async fn simulate(&mut self, req: SimulateRequest) -> Result<SimulateResponse>;
        async fn tx(&mut self, req: GetTxRequest) -> Result<GetTxResponse>;
        async fn account(&mut self, req: QueryAccountRequest) -> Result<QueryAccountResponse>;
        async fn balance(&mut self, req: QueryBalanceRequest) -> Result<QueryBalanceResponse>;
        async fn smart_contract_state(
            &mut self,
            req: QuerySmartContractStateRequest,
        ) -> Result<QuerySmartContractStateResponse>;
    }
}

#[async_trait]
pub trait CosmosClient {
    async fn broadcast_tx(&mut self, req: BroadcastTxRequest) -> Result<BroadcastTxResponse>;
    async fn simulate(&mut self, req: SimulateRequest) -> Result<SimulateResponse>;
    async fn tx(&mut self, req: GetTxRequest) -> Result<GetTxResponse>;
    async fn account(&mut self, req: QueryAccountRequest) -> Result<QueryAccountResponse>;
    async fn balance(&mut self, req: QueryBalanceRequest) -> Result<QueryBalanceResponse>;
    async fn smart_contract_state(
        &mut self,
        req: QuerySmartContractStateRequest,
    ) -> Result<QuerySmartContractStateResponse>;
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
    cosm_wasm: CosmWasmQueryClient<Channel>,
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
            cosm_wasm: CosmWasmQueryClient::new(conn.clone()),
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

    async fn account(&mut self, req: QueryAccountRequest) -> Result<QueryAccountResponse> {
        self.auth
            .account(req)
            .await
            .map(Response::into_inner)
            .map_err(ErrorExt::into_report)
    }

    async fn balance(&mut self, req: QueryBalanceRequest) -> Result<QueryBalanceResponse> {
        self.bank
            .balance(req)
            .await
            .map(Response::into_inner)
            .map_err(ErrorExt::into_report)
    }

    async fn smart_contract_state(
        &mut self,
        req: QuerySmartContractStateRequest,
    ) -> Result<QuerySmartContractStateResponse> {
        self.cosm_wasm
            .smart_contract_state(req)
            .await
            .map(Response::into_inner)
            .map_err(ErrorExt::into_report)
    }
}

impl Debug for CosmosGrpcClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CosmosGrpcClient")
            .field("auth", &REDACTED_VALUE)
            .field("bank", &REDACTED_VALUE)
            .field("cosm_wasm", &REDACTED_VALUE)
            .field("service", &REDACTED_VALUE)
            .finish()
    }
}

pub async fn estimate_gas<T>(
    client: &mut T,
    msgs: Vec<Any>,
    pub_key: CosmosPublicKey,
    acc_sequence: u64,
) -> Result<Gas>
where
    T: CosmosClient,
{
    let tx_bytes = Tx::builder()
        .msgs(msgs)
        .pub_key(pub_key)
        .acc_sequence(acc_sequence)
        .build()
        .with_dummy_sig()
        .await
        .expect("dummy signature must be valid")
        .to_bytes()
        .change_context(Error::TxBuilding)?;

    #[allow(deprecated)]
    client
        .simulate(SimulateRequest { tx: None, tx_bytes })
        .await
        .and_then(|res| {
            res.gas_info
                .map(|info| info.gas_used)
                .ok_or(report!(Error::GasInfoMissing))
        })
}

pub async fn account<T>(client: &mut T, address: &TMAddress) -> Result<BaseAccount>
where
    T: CosmosClient,
{
    client
        .account(QueryAccountRequest {
            address: address.to_string(),
        })
        .await
        .and_then(|res| res.account.ok_or(report!(Error::AccountMissing)))
        .and_then(decode_base_account)
}

pub async fn broadcast<T>(client: &mut T, tx: TxRaw) -> Result<TxResponse>
where
    T: CosmosClient,
{
    let tx = BroadcastTxRequest {
        tx_bytes: tx.to_bytes().change_context(Error::TxBuilding)?,
        mode: BroadcastMode::Sync as i32,
    };

    client
        .broadcast_tx(tx)
        .await
        .and_then(|res| res.tx_response.ok_or(report!(Error::TxResponseMissing)))
}

pub async fn balance<T>(client: &mut T, address: &TMAddress, denom: &Denom) -> Result<Coin>
where
    T: CosmosClient,
{
    client
        .balance(QueryBalanceRequest {
            address: address.to_string(),
            denom: denom.to_string(),
        })
        .await
        .and_then(|res| {
            let coin = res.balance.ok_or(report!(Error::BalanceMissing))?;
            let amount = u128::from_str(&coin.amount).change_context(Error::MalformedResponse)?;

            Coin::new(amount, &coin.denom).change_context(Error::MalformedResponse)
        })
}

pub async fn tx<T>(client: &mut T, hash: &str) -> Result<Option<TxResponse>>
where
    T: CosmosClient,
{
    client
        .tx(GetTxRequest {
            hash: hash.to_string(),
        })
        .await
        .map(|res| res.tx_response)
}

pub async fn contract_state<T>(
    client: &mut T,
    address: &TMAddress,
    query: Vec<u8>,
) -> Result<Vec<u8>>
where
    T: CosmosClient,
{
    client
        .smart_contract_state(QuerySmartContractStateRequest {
            address: address.to_string(),
            query_data: query,
        })
        .await
        .map(|res| res.data)
        .map_err(|err| match err.current_context() {
            Error::GrpcRequest(status) if status.code() == Code::Unknown => {
                report!(Error::QueryContractState(status.message().to_string()))
            }
            _ => err,
        })
}

fn decode_base_account(account: Any) -> Result<BaseAccount> {
    BaseAccount::decode(&account.value[..]).change_context(Error::MalformedResponse)
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::assert_err_contains;
    use cosmrs::proto::cosmos::auth::v1beta1::BaseAccount;
    use cosmrs::proto::cosmos::base::abci::v1beta1::{
        AbciMessageLog, Attribute, GasInfo, Result as AbciResult, StringEvent, TxResponse,
    };
    use cosmrs::proto::cosmos::base::v1beta1::Coin;
    use cosmrs::proto::cosmos::tx::v1beta1::{BroadcastMode, Tx};
    use cosmrs::tx::MessageExt;
    use cosmrs::Any;
    use mockall::predicate;
    use serde_json::json;
    use tendermint_proto::abci;

    use super::*;
    use crate::types::random_cosmos_public_key;
    use crate::PREFIX;

    #[tokio::test]
    async fn estimate_gas_success() {
        let pub_key = random_cosmos_public_key();
        let acc_sequence = 5u64;
        let msgs = vec![Any {
            type_url: "/cosmos.bank.v1beta1.MsgSend".to_string(),
            value: vec![1, 2, 3],
        }];
        let gas_used = 150000u64;

        let mut mock_client = MockCosmosClient::new();
        mock_client.expect_simulate().return_once(move |_| {
            Ok(SimulateResponse {
                gas_info: Some(cosmrs::proto::cosmos::base::abci::v1beta1::GasInfo {
                    gas_wanted: 200000,
                    gas_used,
                }),
                result: None,
            })
        });

        let actual = estimate_gas(&mut mock_client, msgs, pub_key, acc_sequence).await;

        assert_eq!(actual.unwrap(), gas_used);
    }

    #[tokio::test]
    async fn estimate_gas_missing_gas_info() {
        let pub_key = random_cosmos_public_key();
        let acc_sequence = 5u64;
        let msgs = vec![Any {
            type_url: "/cosmos.bank.v1beta1.MsgSend".to_string(),
            value: vec![1, 2, 3],
        }];

        let mut mock_client = MockCosmosClient::new();
        mock_client.expect_simulate().return_once(|_| {
            Ok(SimulateResponse {
                gas_info: None,
                result: None,
            })
        });

        let actual = estimate_gas(&mut mock_client, msgs, pub_key, acc_sequence).await;

        assert_err_contains!(actual, Error, Error::GasInfoMissing);
    }

    #[tokio::test]
    async fn account_success() {
        let address = TMAddress::random(PREFIX);
        let base_account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number: 42,
            sequence: 10,
        };
        let base_account_any = Any::from_msg(&base_account).unwrap();

        let mut mock_client = MockCosmosClient::new();
        mock_client
            .expect_account()
            .with(predicate::eq(QueryAccountRequest {
                address: address.to_string(),
            }))
            .return_once(move |_| {
                Ok(QueryAccountResponse {
                    account: Some(base_account_any),
                })
            });

        let actual = account(&mut mock_client, &address).await;

        assert_eq!(actual.unwrap(), base_account);
    }

    #[tokio::test]
    async fn account_account_missing() {
        let address = TMAddress::random(PREFIX);

        let mut mock_client = MockCosmosClient::new();
        mock_client
            .expect_account()
            .with(predicate::eq(QueryAccountRequest {
                address: address.to_string(),
            }))
            .return_once(move |_| Ok(QueryAccountResponse { account: None }));

        let actual = account(&mut mock_client, &address).await;

        assert_err_contains!(actual, Error, Error::AccountMissing);
    }

    #[tokio::test]
    async fn account_malformed_response() {
        let address = TMAddress::random(PREFIX);

        let mut mock_client = MockCosmosClient::new();
        mock_client
            .expect_account()
            .with(predicate::eq(QueryAccountRequest {
                address: address.to_string(),
            }))
            .return_once(move |_| {
                Ok(QueryAccountResponse {
                    account: Some(Any {
                        type_url: "/cosmos.bank.v1beta1.MsgSend".to_string(),
                        value: vec![1, 2, 3],
                    }),
                })
            });

        let actual = account(&mut mock_client, &address).await;

        assert_err_contains!(actual, Error, Error::MalformedResponse);
    }

    #[tokio::test]
    async fn balance_success() {
        let address = TMAddress::random(PREFIX);
        let denom = Denom::from_str("uaxl").unwrap();
        let amount = 1000000u128;
        let expected_coin = cosmrs::Coin::new(amount, denom.as_ref()).unwrap();

        let mut mock_client = MockCosmosClient::new();
        mock_client
            .expect_balance()
            .with(predicate::eq(QueryBalanceRequest {
                address: address.to_string(),
                denom: denom.to_string(),
            }))
            .return_once(move |_| {
                Ok(QueryBalanceResponse {
                    balance: Some(Coin {
                        denom: "uaxl".to_string(),
                        amount: amount.to_string(),
                    }),
                })
            });

        let actual = balance(&mut mock_client, &address, &denom).await;

        assert_eq!(actual.unwrap(), expected_coin);
    }

    #[tokio::test]
    async fn balance_balance_missing() {
        let address = TMAddress::random(PREFIX);
        let denom = Denom::from_str("uaxl").unwrap();

        let mut mock_client = MockCosmosClient::new();
        mock_client
            .expect_balance()
            .with(predicate::eq(QueryBalanceRequest {
                address: address.to_string(),
                denom: denom.to_string(),
            }))
            .return_once(move |_| Ok(QueryBalanceResponse { balance: None }));

        let actual = balance(&mut mock_client, &address, &denom).await;

        assert_err_contains!(actual, Error, Error::BalanceMissing);
    }

    #[tokio::test]
    async fn balance_malformed_amount() {
        let address = TMAddress::random(PREFIX);
        let denom = Denom::from_str("uaxl").unwrap();

        let mut mock_client = MockCosmosClient::new();
        mock_client
            .expect_balance()
            .with(predicate::eq(QueryBalanceRequest {
                address: address.to_string(),
                denom: denom.to_string(),
            }))
            .return_once(move |_| {
                Ok(QueryBalanceResponse {
                    balance: Some(Coin {
                        denom: "uaxl".to_string(),
                        amount: "not-a-number".to_string(),
                    }),
                })
            });

        let actual = balance(&mut mock_client, &address, &denom).await;

        assert_err_contains!(actual, Error, Error::MalformedResponse);
    }

    #[tokio::test]
    async fn balance_malformed_denom() {
        let address = TMAddress::random(PREFIX);
        let denom = Denom::from_str("uaxl").unwrap();

        let mut mock_client = MockCosmosClient::new();
        mock_client
            .expect_balance()
            .with(predicate::eq(QueryBalanceRequest {
                address: address.to_string(),
                denom: denom.to_string(),
            }))
            .return_once(move |_| {
                Ok(QueryBalanceResponse {
                    balance: Some(Coin {
                        denom: "uaxl_-=".to_string(),
                        amount: "10000".to_string(),
                    }),
                })
            });

        let actual = balance(&mut mock_client, &address, &denom).await;

        assert_err_contains!(actual, Error, Error::MalformedResponse);
    }

    #[tokio::test]
    async fn tx_success() {
        let tx_hash = "ABC123";
        let expected_response = TxResponse {
            height: 100,
            txhash: tx_hash.to_string(),
            ..Default::default()
        };

        let expected_response_clone = expected_response.clone();
        let mut mock_client = MockCosmosClient::new();
        mock_client
            .expect_tx()
            .with(predicate::eq(GetTxRequest {
                hash: tx_hash.to_string(),
            }))
            .return_once(move |_| {
                Ok(GetTxResponse {
                    tx: None,
                    tx_response: Some(expected_response_clone),
                })
            });

        let actual = tx(&mut mock_client, tx_hash).await;

        assert_eq!(actual.unwrap(), Some(expected_response));
    }

    #[tokio::test]
    async fn tx_not_found() {
        let tx_hash = "NONEXISTENT";

        let mut mock_client = MockCosmosClient::new();
        mock_client
            .expect_tx()
            .with(predicate::eq(GetTxRequest {
                hash: tx_hash.to_string(),
            }))
            .return_once(move |_| {
                Ok(GetTxResponse {
                    tx: None,
                    tx_response: None,
                })
            });

        let actual = tx(&mut mock_client, tx_hash).await;

        assert_eq!(actual.unwrap(), None);
    }

    #[tokio::test]
    async fn broadcast_success() {
        let tx_raw = TxRaw {
            body_bytes: vec![1, 2, 3],
            auth_info_bytes: vec![4, 5, 6],
            signatures: vec![vec![7, 8, 9]],
        };

        let mut mock_client = MockCosmosClient::new();
        mock_client
            .expect_broadcast_tx()
            .withf(|req| req.mode == BroadcastMode::Sync as i32)
            .return_once(|_| {
                Ok(BroadcastTxResponse {
                    tx_response: Some(TxResponse {
                        txhash: "ABC123".to_string(),
                        ..Default::default()
                    }),
                })
            });

        let actual = broadcast(&mut mock_client, tx_raw).await;

        assert_eq!(actual.unwrap().txhash, "ABC123");
    }

    #[tokio::test]
    async fn broadcast_tx_response_missing() {
        let tx_raw = TxRaw {
            body_bytes: vec![1, 2, 3],
            auth_info_bytes: vec![4, 5, 6],
            signatures: vec![vec![7, 8, 9]],
        };

        let mut mock_client = MockCosmosClient::new();
        mock_client
            .expect_broadcast_tx()
            .return_once(|_| Ok(BroadcastTxResponse { tx_response: None }));

        let actual = broadcast(&mut mock_client, tx_raw).await;

        assert_err_contains!(actual, Error, Error::TxResponseMissing);
    }

    #[tokio::test]
    async fn contract_state_success() {
        let address = TMAddress::random(PREFIX);
        let query = serde_json::to_vec(&json!({"get_count": {}})).unwrap();
        let expected = vec![1, 2, 3, 4];

        let mut mock_client = MockCosmosClient::new();
        mock_client
            .expect_smart_contract_state()
            .with(predicate::eq(QuerySmartContractStateRequest {
                address: address.to_string(),
                query_data: query.clone(),
            }))
            .return_once(|_| {
                Ok(QuerySmartContractStateResponse {
                    data: vec![1, 2, 3, 4],
                })
            });

        let actual = contract_state(&mut mock_client, &address, query).await;

        assert_eq!(actual.unwrap(), expected);
    }

    #[tokio::test]
    async fn contract_state_contract_error() {
        let address = TMAddress::random(PREFIX);
        let query = serde_json::to_vec(&json!({"invalid_query": {}})).unwrap();

        let mut mock_client = MockCosmosClient::new();
        mock_client
            .expect_smart_contract_state()
            .with(predicate::eq(QuerySmartContractStateRequest {
                address: address.to_string(),
                query_data: query.clone(),
            }))
            .return_once(move |_| {
                Err(report!(Error::GrpcRequest(Status::new(
                    Code::Unknown,
                    "query not supported"
                ))))
            });

        let actual = contract_state(&mut mock_client, &address, query).await;

        assert_err_contains!(actual, Error, Error::QueryContractState(_));
    }

    #[tokio::test]
    async fn contract_state_network_error() {
        let address = TMAddress::random(PREFIX);
        let query = serde_json::to_vec(&json!({"get_count": {}})).unwrap();

        let mut mock_client = MockCosmosClient::new();
        mock_client
            .expect_smart_contract_state()
            .with(predicate::eq(QuerySmartContractStateRequest {
                address: address.to_string(),
                query_data: query.clone(),
            }))
            .return_once(move |_| {
                Err(report!(Error::GrpcRequest(Status::new(
                    Code::Unavailable,
                    "connection error"
                ))))
            });

        let actual = contract_state(&mut mock_client, &address, query).await;

        assert_err_contains!(actual, Error, Error::GrpcRequest(_));
    }

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
                tx: Some(Any {
                    type_url: "axelar.type".to_string(),
                    value: vec![1, 2, 3, 4, 5, 6],
                }),
                timestamp: "timestamp".to_string(),
                events: vec![abci::Event {
                    r#type: "event_type".to_string(),
                    attributes: vec![abci::EventAttribute {
                        index: true,
                        key: "key".to_string(),
                        value: "value".to_string(),
                    }],
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
                    r#type: "simulation_event".to_string(),
                    attributes: vec![abci::EventAttribute {
                        index: true,
                        key: "sim_key".to_string(),
                        value: "sim_value".to_string(),
                    }],
                }],
                msg_responses: vec![Any {
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
                tx: Some(Any {
                    type_url: "/cosmos.tx.v1beta1.Tx".to_string(),
                    value: vec![10, 20, 30, 40, 50],
                }),
                timestamp: "2025-04-23T17:00:00Z".to_string(),
                events: vec![abci::Event {
                    r#type: "tx_result_event".to_string(),
                    attributes: vec![abci::EventAttribute {
                        index: true,
                        key: "tx_result_key".to_string(),
                        value: "tx_result_value".to_string(),
                    }],
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
    fn ensure_account_req_res_serialization_do_not_change() {
        let req = QueryAccountRequest {
            address: "axelar1q95p9fntvqn6jm9m0u5092pu9ulq3chn0zkuks".to_string(),
        };
        let base_account = BaseAccount {
            address: "axelar1q95p9fntvqn6jm9m0u5092pu9ulq3chn0zkuks".to_string(),
            pub_key: Some(Any {
                type_url: "/cosmos.crypto.secp256k1.PubKey".to_string(),
                value: vec![
                    10, 33, 2, 136, 177, 245, 49, 184, 120, 113, 219, 192, 55, 41, 81,
                ],
            }),
            account_number: 42,
            sequence: 7,
        };
        let res = QueryAccountResponse {
            account: Some(Any::from_msg(&base_account).unwrap()),
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

    #[test]
    fn ensure_smart_contract_state_req_res_serialization_do_not_change() {
        let req = QuerySmartContractStateRequest {
            address: "axelar1q95p9fntvqn6jm9m0u5092pu9ulq3chn0zkuks".to_string(),
            query_data: serde_json::to_vec(&json!({"get_config": {}})).unwrap(),
        };
        let res = QuerySmartContractStateResponse {
            data: serde_json::to_vec(&json!({
                "name": "axelar-gateway",
                "version": "1.0.0",
                "owner": "axelar1q95p9fntvqn6jm9m0u5092pu9ulq3chn0zkuks",
                "config": {
                    "chain_id": "axelar-testnet-1",
                    "enabled": true
                }
            }))
            .unwrap(),
        };

        goldie::assert_json!(json!({
            "req": format!("{:?}", req),
            "res": format!("{:?}", res),
            "req_bytes": req.to_bytes().unwrap(),
            "res_bytes": res.to_bytes().unwrap()
        }));
    }
}
