use std::{collections::HashMap, sync::Arc};

use serde_json::{json, Value};
use solana_client::{
     nonblocking::rpc_client::RpcClient, rpc_client::RpcClientConfig, rpc_request::RpcRequest, rpc_response::{Response, RpcResponseContext, RpcVersionInfo}, rpc_sender::{RpcSender, RpcTransportStats}
};
use solana_sdk::{message::MessageHeader, transaction::TransactionVersion};
use solana_transaction_status::{option_serializer::OptionSerializer, EncodedConfirmedTransactionWithStatusMeta, EncodedTransaction, EncodedTransactionWithStatusMeta, UiCompiledInstruction, UiMessage, UiRawMessage, UiTransaction, UiTransactionStatusMeta};
use solana_version::Version;

use solana_rpc_client_api::client_error::Result;
use tokio::sync::RwLock;
use tonic::async_trait;

type Registry = Arc<RwLock<HashMap<RpcRequest, u64>>>;

pub struct RpcRecorder {
    record: Arc<RwLock<HashMap<RpcRequest, u64>>>,
}

impl RpcRecorder {
    pub fn new() -> (Self, Registry) {
        let registry = Arc::new(RwLock::new(HashMap::new()));
        let self_v  = Self {
            record: registry.clone(),
        };
        (self_v, registry)
    }   
}

/// Reference: https://docs.rs/solana-rpc-client/1.18.3/src/solana_rpc_client/mock_sender.rs.html#97-488
#[async_trait]
impl RpcSender for RpcRecorder {
    fn get_transport_stats(&self) -> RpcTransportStats {
        RpcTransportStats::default()
    }

    async fn send(
        &self,
        request: RpcRequest,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {

        let mut acquired_record = self.record.write().await;       

        acquired_record
        .entry(request)
        .and_modify(|count| *count = count.checked_add(1).unwrap())
        .or_insert(1);

        let method = &request.build_request_json(42, params.clone())["method"];      

        let val = match method.as_str().unwrap() {
            "getAccountInfo" => serde_json::to_value(Response {
                context: RpcResponseContext { slot: 1, api_version: None },
                value: Value::Null,
            })?,          
            "getTransaction" => serde_json::to_value(EncodedConfirmedTransactionWithStatusMeta {
                slot: 2,
                transaction: EncodedTransactionWithStatusMeta {
                    version: Some(TransactionVersion::LEGACY),
                    transaction: EncodedTransaction::Json(
                        UiTransaction {
                            signatures: vec!["3AsdoALgZFuq2oUVWrDYhg2pNeaLJKPLf8hU2mQ6U8qJxeJ6hsrPVpMn9ma39DtfYCrDQSvngWRP8NnTpEhezJpE".to_string()],
                            message: UiMessage::Raw(
                                UiRawMessage {
                                    header: MessageHeader {
                                        num_required_signatures: 1,
                                        num_readonly_signed_accounts: 0,
                                        num_readonly_unsigned_accounts: 1,
                                    },
                                    account_keys: vec![
                                        "C6eBmAXKg6JhJWkajGa5YRGUfG4YKXwbxF5Ufv7PtExZ".to_string(),
                                        "2Gd5eoR5J4BV89uXbtunpbNhjmw3wa1NbRHxTHzDzZLX".to_string(),
                                        "11111111111111111111111111111111".to_string(),
                                    ],
                                    recent_blockhash: "D37n3BSG71oUWcWjbZ37jZP7UfsxG2QMKeuALJ1PYvM6".to_string(),
                                    instructions: vec![UiCompiledInstruction {
                                        program_id_index: 2,
                                        accounts: vec![0, 1],
                                        data: "3Bxs49DitAvXtoDR".to_string(),
                                        stack_height: None,
                                    }],
                                    address_table_lookups: None,
                                })
                        }),
                    meta: Some(UiTransactionStatusMeta {
                            err: None,
                            status: Ok(()),
                            fee: 0,
                            pre_balances: vec![499999999999999950, 50, 1],
                            post_balances: vec![499999999999999950, 50, 1],
                            inner_instructions: OptionSerializer::None,
                            log_messages: OptionSerializer::None,
                            pre_token_balances: OptionSerializer::None,
                            post_token_balances: OptionSerializer::None,
                            rewards: OptionSerializer::None,
                            loaded_addresses: OptionSerializer::Skip,
                            return_data: OptionSerializer::Skip,
                            compute_units_consumed: OptionSerializer::Skip,
                        }),
                },
                block_time: Some(1628633791),
            })?,            
            "getVersion" => {
                let version = Version::default();
                json!(RpcVersionInfo {
                    solana_core: version.to_string(),
                    feature_set: Some(version.feature_set),
                })
            }
            _ => Value::Null,
        };
        Ok(val)
    }

    fn url(&self) -> String {
        "MockSender".to_string()
    }
}

pub fn rpc_client_with_recorder() -> (RpcClient, Registry) {
    let (rpc_recorder, registry) = RpcRecorder::new();
    let rpc_client = RpcClient::new_sender(rpc_recorder, RpcClientConfig::default());
    (rpc_client, registry)
}