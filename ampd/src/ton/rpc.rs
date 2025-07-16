use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axelar_wasm_std::msg_id::HexTxHash;
use error_stack::{report, ResultExt};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tonlib_core::cell::Cell;
use tonlib_core::tlb_types::traits::TLBObject;
use tonlib_core::TonAddress;
use tracing::warn;

use crate::handlers::ton_verify_msg::FetchingError;

pub struct TonRpcClient {
    rpc_url: String,
    client: Client,
}

impl TonRpcClient {
    pub fn new(rpc_url: &str) -> Self {
        let client = Client::new();
        TonRpcClient {
            rpc_url: rpc_url.to_owned(),
            client,
        }
    }
}

#[derive(Debug)]
pub struct TonLog {
    pub opcode: u32,
    pub cell: Arc<Cell>,
}

#[async_trait::async_trait]
pub trait TonClient: Send + Sync + 'static {
    async fn get_log(
        &self,
        contract_address: &TonAddress,
        tx_hash: &HexTxHash,
    ) -> error_stack::Result<TonLog, FetchingError>;
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionsResponse {
    pub transactions: Vec<Transaction>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Transaction {
    pub account: String,
    pub hash: String,
    pub description: TransactionDescription,
    pub in_msg: TransactionMessage,
    pub out_msgs: Vec<TransactionMessage>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransactionDescription {
    pub aborted: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransactionMessage {
    pub hash: String,
    pub opcode: String,
    pub message_content: MessageContent,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MessageContent {
    pub body: String,
}

pub(crate) fn extract_body(
    contract_address: &TonAddress,
    rpc_response: &str,
) -> error_stack::Result<TonLog, FetchingError> {
    let result: TransactionsResponse =
        serde_json::from_str(rpc_response).change_context(FetchingError::Client)?;

    let transactions = result.transactions;

    if transactions.is_empty() {
        return Err(report!(FetchingError::NotFound));
    }

    let transaction = &transactions[0];

    let address =
        TonAddress::from_hex_str(&transaction.account).change_context(FetchingError::Client)?;

    if address != *contract_address {
        return Err(report!(FetchingError::InvalidCall));
    }

    if transaction.description.aborted {
        return Err(report!(FetchingError::InvalidCall));
    }

    let opcode = u32::from_str_radix(transaction.in_msg.opcode.trim_start_matches("0x"), 16)
        .change_context(FetchingError::Client)?;

    if transaction.out_msgs.is_empty() {
        return Err(report!(FetchingError::InvalidCall));
    }

    let log = &transaction.out_msgs[0];
    let log_body = &log.message_content.body;

    match Cell::from_boc_b64(log_body).and_then(|c| Arc::from_cell(&c)) {
        Ok(cell) => Ok(TonLog { opcode, cell }),
        Err(_) => Err(report!(FetchingError::Client)),
    }
}

#[async_trait]
impl TonClient for TonRpcClient {
    async fn get_log(
        &self,
        contract_address: &TonAddress,
        tx_hash: &HexTxHash,
    ) -> error_stack::Result<TonLog, FetchingError> {
        let mut data: HashMap<String, String> = HashMap::new();
        data.insert(
            "hash".to_string(),
            tx_hash.tx_hash_as_hex_no_prefix().to_string(),
        );

        let method = "transactions";

        let res = self
            .client
            .get(format!("{}/{}", self.rpc_url, method))
            .query(&data)
            .send()
            .await
            .change_context(FetchingError::Client)?;

        let status = res.status();
        let text = res.text().await.change_context(FetchingError::Client)?;

        if !status.is_success() {
            warn!("RPC query failed");
            return Err(report!(FetchingError::Client));
        }

        extract_body(contract_address, &text)
    }
}

#[cfg(test)]
mod tests {
    use goldie::assert_debug;
    use tonlib_core::TonAddress;

    use crate::ton::rpc::extract_body;

    #[test]
    fn should_correctly_parse_call_contract() {
        let rpc_return_text = r#"{"transactions":[{"account":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","hash":"L/DSNQ43lWUDdga8h4ci8hVp+nVS6/BxEF7KrAO0yTo=","lt":"36582626000003","now":1751972976,"mc_block_seqno":33013054,"trace_id":"6h4rXxxaXBcwgFnNiyyzXolMBo6wDeqiW2+LIq8feHE=","prev_trans_hash":"BoNe1HOkg+5k8XGGuY5iRcuz8Nwkc5rxT7NuM/vDP/E=","prev_trans_lt":"36552848000003","orig_status":"active","end_status":"active","total_fees":"6617389","total_fees_extra_currencies":{},"description":{"type":"ord","aborted":false,"destroyed":false,"credit_first":false,"storage_ph":{"storage_fees_collected":"72858","status_change":"unchanged"},"credit_ph":{"credit":"98993600"},"compute_ph":{"skipped":false,"success":true,"msg_state_used":false,"account_activated":false,"gas_fees":"5138000","gas_used":"12845","gas_limit":"247484","mode":0,"exit_code":0,"vm_steps":274,"vm_init_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","vm_final_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"action":{"success":true,"valid":true,"no_funds":false,"status_change":"unchanged","total_fwd_fees":"1708400","total_action_fees":"1406531","result_code":0,"tot_actions":2,"spec_actions":0,"skipped_actions":0,"msgs_created":2,"action_list_hash":"hBjjQRhmPzm+RKgy6U+Ege0Hb0UxD5cNxn2hErwF/To=","tot_msg_size":{"cells":"7","bits":"3110"}}},"block_ref":{"workchain":0,"shard":"8000000000000000","seqno":34903585},"in_msg":{"hash":"59r5FWJBKUv8C7E2szCKDhjdsz0t9hLJM5OiFHToemc=","source":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","destination":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","value":"98993600","value_extra_currencies":{},"fwd_fee":"670939","ihr_fee":"0","created_lt":"36582626000002","created_at":"1751972976","opcode":"0x00000009","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"o7V4cZZJdfDYiGUOySLXQiP8zq9cSASvIlmbO/ucJzI=","body":"te6cckEBBAEApwADCAAAAAkBAgMAHGF2YWxhbmNoZS1mdWppAFQweGQ3MDY3QWUzQzM1OWU4Mzc4OTBiMjhCN0JEMGQyMDg0Q2ZEZjQ5YjUAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABNIZWxsbyBmcm9tIFJlbGF5ZXIhAAAAAAAAAAAAAAAAAGu4UHQ=","decoded":null},"init_state":null},"out_msgs":[{"hash":"WsQVGIoOXjS+BqJ46ebFGmzBUNGOY3t2DbZ1/EXK9h4=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":null,"value":null,"value_extra_currencies":null,"fwd_fee":null,"ihr_fee":null,"created_lt":"36582626000004","created_at":"1751972976","opcode":"0x8011315a","ihr_disabled":null,"bounce":null,"bounced":null,"import_fee":null,"message_content":{"hash":"laYhaSZO6QjQmRsJsn02MK8hcwwIgxMIYX2oFcjFNdA=","body":"te6cckEBBAEA5QADg4ARMVongLPlR00q7UAhiDXkc2kPeKq9V9c0sSm9YiUyZhXUykhs4AH2lBVEFjqex7VaPbPTvuLH5GEs5sIeXm+pcAECAwAcYXZhbGFuY2hlLWZ1amkAVDB4ZDcwNjdBZTNDMzU5ZTgzNzg5MGIyOEI3QkQwZDIwODRDZkRmNDliNQDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE0hlbGxvIGZyb20gUmVsYXllciEAAAAAAAAAAAAAAAAALSbhEA==","decoded":null},"init_state":null},{"hash":"5+pjUx9a/8fmExUlLPQKUWSf+p+/HGhbuiL6Trhuufw=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","value":"93402800","value_extra_currencies":{},"fwd_fee":"301869","ihr_fee":"0","created_lt":"36582626000005","created_at":"1751972976","opcode":"0x00000018","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"qvrlOoIcMk+4fXd5wBBiFUGFVRoCDCkhuAdj+PADXBE=","body":"te6cckEBAQEABgAACAAAABhDnyiV","decoded":null},"init_state":null}],"account_state_before":{"hash":"posCwcSHfOabFTEJpZf3DjjrwdCa0yhl9DX9LTojxY4=","balance":"2717267789","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"account_state_after":{"hash":"4OBdR8k83rjRSwwreZI6a8TmlsuKN5MrCbM/6B+8bFw=","balance":"2715939331","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"emulated":false}]}"#;
        let example_gateway =
            TonAddress::from_base64_url("kQAAGUqtjkIr7fQ_7nRtbZKdNp26slRopp1RNwbqaXi2OnXH")
                .unwrap();

        let log = extract_body(&example_gateway, rpc_return_text)
            .expect("Example RPC return text should be parsable");
        assert_debug!(log);
    }

    #[test]
    fn should_not_parse_invalid_call_contract() {
        let rpc_return_text_non_json = r#"{"transactions":[{account":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","hash":"L/DSNQ43lWUDdga8h4ci8hVp+nVS6/BxEF7KrAO0yTo=","lt":"36582626000003","now":1751972976,"mc_block_seqno":33013054,"trace_id":"6h4rXxxaXBcwgFnNiyyzXolMBo6wDeqiW2+LIq8feHE=","prev_trans_hash":"BoNe1HOkg+5k8XGGuY5iRcuz8Nwkc5rxT7NuM/vDP/E=","prev_trans_lt":"36552848000003","orig_status":"active","end_status":"active","total_fees":"6617389","total_fees_extra_currencies":{},"description":{"type":"ord","aborted":false,"destroyed":false,"credit_first":false,"storage_ph":{"storage_fees_collected":"72858","status_change":"unchanged"},"credit_ph":{"credit":"98993600"},"compute_ph":{"skipped":false,"success":true,"msg_state_used":false,"account_activated":false,"gas_fees":"5138000","gas_used":"12845","gas_limit":"247484","mode":0,"exit_code":0,"vm_steps":274,"vm_init_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","vm_final_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"action":{"success":true,"valid":true,"no_funds":false,"status_change":"unchanged","total_fwd_fees":"1708400","total_action_fees":"1406531","result_code":0,"tot_actions":2,"spec_actions":0,"skipped_actions":0,"msgs_created":2,"action_list_hash":"hBjjQRhmPzm+RKgy6U+Ege0Hb0UxD5cNxn2hErwF/To=","tot_msg_size":{"cells":"7","bits":"3110"}}},"block_ref":{"workchain":0,"shard":"8000000000000000","seqno":34903585},"in_msg":{"hash":"59r5FWJBKUv8C7E2szCKDhjdsz0t9hLJM5OiFHToemc=","source":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","destination":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","value":"98993600","value_extra_currencies":{},"fwd_fee":"670939","ihr_fee":"0","created_lt":"36582626000002","created_at":"1751972976","opcode":"0x00000009","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"o7V4cZZJdfDYiGUOySLXQiP8zq9cSASvIlmbO/ucJzI=","body":"te6cckEBBAEApwADCAAAAAkBAgMAHGF2YWxhbmNoZS1mdWppAFQweGQ3MDY3QWUzQzM1OWU4Mzc4OTBiMjhCN0JEMGQyMDg0Q2ZEZjQ5YjUAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABNIZWxsbyBmcm9tIFJlbGF5ZXIhAAAAAAAAAAAAAAAAAGu4UHQ=","decoded":null},"init_state":null},"out_msgs":[{"hash":"WsQVGIoOXjS+BqJ46ebFGmzBUNGOY3t2DbZ1/EXK9h4=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":null,"value":null,"value_extra_currencies":null,"fwd_fee":null,"ihr_fee":null,"created_lt":"36582626000004","created_at":"1751972976","opcode":"0x8011315a","ihr_disabled":null,"bounce":null,"bounced":null,"import_fee":null,"message_content":{"hash":"laYhaSZO6QjQmRsJsn02MK8hcwwIgxMIYX2oFcjFNdA=","body":"te6cckEBBAEA5QADg4ARMVongLPlR00q7UAhiDXkc2kPeKq9V9c0sSm9YiUyZhXUykhs4AH2lBVEFjqex7VaPbPTvuLH5GEs5sIeXm+pcAECAwAcYXZhbGFuY2hlLWZ1amkAVDB4ZDcwNjdBZTNDMzU5ZTgzNzg5MGIyOEI3QkQwZDIwODRDZkRmNDliNQDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE0hlbGxvIGZyb20gUmVsYXllciEAAAAAAAAAAAAAAAAALSbhEA==","decoded":null},"init_state":null},{"hash":"5+pjUx9a/8fmExUlLPQKUWSf+p+/HGhbuiL6Trhuufw=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","value":"93402800","value_extra_currencies":{},"fwd_fee":"301869","ihr_fee":"0","created_lt":"36582626000005","created_at":"1751972976","opcode":"0x00000018","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"qvrlOoIcMk+4fXd5wBBiFUGFVRoCDCkhuAdj+PADXBE=","body":"te6cckEBAQEABgAACAAAABhDnyiV","decoded":null},"init_state":null}],"account_state_before":{"hash":"posCwcSHfOabFTEJpZf3DjjrwdCa0yhl9DX9LTojxY4=","balance":"2717267789","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"account_state_after":{"hash":"4OBdR8k83rjRSwwreZI6a8TmlsuKN5MrCbM/6B+8bFw=","balance":"2715939331","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"emulated":false}]}"#;
        let example_gateway =
            TonAddress::from_base64_url("kQAAGUqtjkIr7fQ_7nRtbZKdNp26slRopp1RNwbqaXi2OnXH")
                .unwrap();

        let log = extract_body(&example_gateway, rpc_return_text_non_json);
        assert!(log.is_err());
    }

    #[test]
    fn should_reject_invalid_call_contract_wrong_contract() {
        let rpc_return_text = r#"{"transactions":[{"account":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","hash":"L/DSNQ43lWUDdga8h4ci8hVp+nVS6/BxEF7KrAO0yTo=","lt":"36582626000003","now":1751972976,"mc_block_seqno":33013054,"trace_id":"6h4rXxxaXBcwgFnNiyyzXolMBo6wDeqiW2+LIq8feHE=","prev_trans_hash":"BoNe1HOkg+5k8XGGuY5iRcuz8Nwkc5rxT7NuM/vDP/E=","prev_trans_lt":"36552848000003","orig_status":"active","end_status":"active","total_fees":"6617389","total_fees_extra_currencies":{},"description":{"type":"ord","aborted":false,"destroyed":false,"credit_first":false,"storage_ph":{"storage_fees_collected":"72858","status_change":"unchanged"},"credit_ph":{"credit":"98993600"},"compute_ph":{"skipped":false,"success":true,"msg_state_used":false,"account_activated":false,"gas_fees":"5138000","gas_used":"12845","gas_limit":"247484","mode":0,"exit_code":0,"vm_steps":274,"vm_init_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","vm_final_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"action":{"success":true,"valid":true,"no_funds":false,"status_change":"unchanged","total_fwd_fees":"1708400","total_action_fees":"1406531","result_code":0,"tot_actions":2,"spec_actions":0,"skipped_actions":0,"msgs_created":2,"action_list_hash":"hBjjQRhmPzm+RKgy6U+Ege0Hb0UxD5cNxn2hErwF/To=","tot_msg_size":{"cells":"7","bits":"3110"}}},"block_ref":{"workchain":0,"shard":"8000000000000000","seqno":34903585},"in_msg":{"hash":"59r5FWJBKUv8C7E2szCKDhjdsz0t9hLJM5OiFHToemc=","source":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","destination":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","value":"98993600","value_extra_currencies":{},"fwd_fee":"670939","ihr_fee":"0","created_lt":"36582626000002","created_at":"1751972976","opcode":"0x00000009","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"o7V4cZZJdfDYiGUOySLXQiP8zq9cSASvIlmbO/ucJzI=","body":"te6cckEBBAEApwADCAAAAAkBAgMAHGF2YWxhbmNoZS1mdWppAFQweGQ3MDY3QWUzQzM1OWU4Mzc4OTBiMjhCN0JEMGQyMDg0Q2ZEZjQ5YjUAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABNIZWxsbyBmcm9tIFJlbGF5ZXIhAAAAAAAAAAAAAAAAAGu4UHQ=","decoded":null},"init_state":null},"out_msgs":[{"hash":"WsQVGIoOXjS+BqJ46ebFGmzBUNGOY3t2DbZ1/EXK9h4=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":null,"value":null,"value_extra_currencies":null,"fwd_fee":null,"ihr_fee":null,"created_lt":"36582626000004","created_at":"1751972976","opcode":"0x8011315a","ihr_disabled":null,"bounce":null,"bounced":null,"import_fee":null,"message_content":{"hash":"laYhaSZO6QjQmRsJsn02MK8hcwwIgxMIYX2oFcjFNdA=","body":"te6cckEBBAEA5QADg4ARMVongLPlR00q7UAhiDXkc2kPeKq9V9c0sSm9YiUyZhXUykhs4AH2lBVEFjqex7VaPbPTvuLH5GEs5sIeXm+pcAECAwAcYXZhbGFuY2hlLWZ1amkAVDB4ZDcwNjdBZTNDMzU5ZTgzNzg5MGIyOEI3QkQwZDIwODRDZkRmNDliNQDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE0hlbGxvIGZyb20gUmVsYXllciEAAAAAAAAAAAAAAAAALSbhEA==","decoded":null},"init_state":null},{"hash":"5+pjUx9a/8fmExUlLPQKUWSf+p+/HGhbuiL6Trhuufw=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","value":"93402800","value_extra_currencies":{},"fwd_fee":"301869","ihr_fee":"0","created_lt":"36582626000005","created_at":"1751972976","opcode":"0x00000018","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"qvrlOoIcMk+4fXd5wBBiFUGFVRoCDCkhuAdj+PADXBE=","body":"te6cckEBAQEABgAACAAAABhDnyiV","decoded":null},"init_state":null}],"account_state_before":{"hash":"posCwcSHfOabFTEJpZf3DjjrwdCa0yhl9DX9LTojxY4=","balance":"2717267789","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"account_state_after":{"hash":"4OBdR8k83rjRSwwreZI6a8TmlsuKN5MrCbM/6B+8bFw=","balance":"2715939331","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"emulated":false}]}"#;
        let example_gateway =
            TonAddress::from_base64_url("EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs")
                .unwrap();

        let log = extract_body(&example_gateway, rpc_return_text);
        assert!(log.is_err());
    }

    #[test]
    fn should_reject_invalid_call_contract_aborted() {
        // notice "aborted" is true
        let rpc_return_text = r#"{"transactions":[{"account":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","hash":"L/DSNQ43lWUDdga8h4ci8hVp+nVS6/BxEF7KrAO0yTo=","lt":"36582626000003","now":1751972976,"mc_block_seqno":33013054,"trace_id":"6h4rXxxaXBcwgFnNiyyzXolMBo6wDeqiW2+LIq8feHE=","prev_trans_hash":"BoNe1HOkg+5k8XGGuY5iRcuz8Nwkc5rxT7NuM/vDP/E=","prev_trans_lt":"36552848000003","orig_status":"active","end_status":"active","total_fees":"6617389","total_fees_extra_currencies":{},"description":{"type":"ord","aborted":true,"destroyed":false,"credit_first":false,"storage_ph":{"storage_fees_collected":"72858","status_change":"unchanged"},"credit_ph":{"credit":"98993600"},"compute_ph":{"skipped":false,"success":true,"msg_state_used":false,"account_activated":false,"gas_fees":"5138000","gas_used":"12845","gas_limit":"247484","mode":0,"exit_code":0,"vm_steps":274,"vm_init_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","vm_final_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"action":{"success":true,"valid":true,"no_funds":false,"status_change":"unchanged","total_fwd_fees":"1708400","total_action_fees":"1406531","result_code":0,"tot_actions":2,"spec_actions":0,"skipped_actions":0,"msgs_created":2,"action_list_hash":"hBjjQRhmPzm+RKgy6U+Ege0Hb0UxD5cNxn2hErwF/To=","tot_msg_size":{"cells":"7","bits":"3110"}}},"block_ref":{"workchain":0,"shard":"8000000000000000","seqno":34903585},"in_msg":{"hash":"59r5FWJBKUv8C7E2szCKDhjdsz0t9hLJM5OiFHToemc=","source":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","destination":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","value":"98993600","value_extra_currencies":{},"fwd_fee":"670939","ihr_fee":"0","created_lt":"36582626000002","created_at":"1751972976","opcode":"0x00000009","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"o7V4cZZJdfDYiGUOySLXQiP8zq9cSASvIlmbO/ucJzI=","body":"te6cckEBBAEApwADCAAAAAkBAgMAHGF2YWxhbmNoZS1mdWppAFQweGQ3MDY3QWUzQzM1OWU4Mzc4OTBiMjhCN0JEMGQyMDg0Q2ZEZjQ5YjUAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABNIZWxsbyBmcm9tIFJlbGF5ZXIhAAAAAAAAAAAAAAAAAGu4UHQ=","decoded":null},"init_state":null},"out_msgs":[{"hash":"WsQVGIoOXjS+BqJ46ebFGmzBUNGOY3t2DbZ1/EXK9h4=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":null,"value":null,"value_extra_currencies":null,"fwd_fee":null,"ihr_fee":null,"created_lt":"36582626000004","created_at":"1751972976","opcode":"0x8011315a","ihr_disabled":null,"bounce":null,"bounced":null,"import_fee":null,"message_content":{"hash":"laYhaSZO6QjQmRsJsn02MK8hcwwIgxMIYX2oFcjFNdA=","body":"te6cckEBBAEA5QADg4ARMVongLPlR00q7UAhiDXkc2kPeKq9V9c0sSm9YiUyZhXUykhs4AH2lBVEFjqex7VaPbPTvuLH5GEs5sIeXm+pcAECAwAcYXZhbGFuY2hlLWZ1amkAVDB4ZDcwNjdBZTNDMzU5ZTgzNzg5MGIyOEI3QkQwZDIwODRDZkRmNDliNQDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE0hlbGxvIGZyb20gUmVsYXllciEAAAAAAAAAAAAAAAAALSbhEA==","decoded":null},"init_state":null},{"hash":"5+pjUx9a/8fmExUlLPQKUWSf+p+/HGhbuiL6Trhuufw=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","value":"93402800","value_extra_currencies":{},"fwd_fee":"301869","ihr_fee":"0","created_lt":"36582626000005","created_at":"1751972976","opcode":"0x00000018","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"qvrlOoIcMk+4fXd5wBBiFUGFVRoCDCkhuAdj+PADXBE=","body":"te6cckEBAQEABgAACAAAABhDnyiV","decoded":null},"init_state":null}],"account_state_before":{"hash":"posCwcSHfOabFTEJpZf3DjjrwdCa0yhl9DX9LTojxY4=","balance":"2717267789","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"account_state_after":{"hash":"4OBdR8k83rjRSwwreZI6a8TmlsuKN5MrCbM/6B+8bFw=","balance":"2715939331","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"emulated":false}]}"#;
        let example_gateway =
            TonAddress::from_base64_url("kQAAGUqtjkIr7fQ_7nRtbZKdNp26slRopp1RNwbqaXi2OnXH")
                .unwrap();

        let log = extract_body(&example_gateway, rpc_return_text);
        assert!(log.is_err());
    }

    #[test]
    fn should_reject_invalid_call_contract_unparsable() {
        // notice "aborted" is "asdf"
        let rpc_return_text = r#"{"transactions":[{"account":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","hash":"L/DSNQ43lWUDdga8h4ci8hVp+nVS6/BxEF7KrAO0yTo=","lt":"36582626000003","now":1751972976,"mc_block_seqno":33013054,"trace_id":"6h4rXxxaXBcwgFnNiyyzXolMBo6wDeqiW2+LIq8feHE=","prev_trans_hash":"BoNe1HOkg+5k8XGGuY5iRcuz8Nwkc5rxT7NuM/vDP/E=","prev_trans_lt":"36552848000003","orig_status":"active","end_status":"active","total_fees":"6617389","total_fees_extra_currencies":{},"description":{"type":"ord","aborted":"asdf","destroyed":false,"credit_first":false,"storage_ph":{"storage_fees_collected":"72858","status_change":"unchanged"},"credit_ph":{"credit":"98993600"},"compute_ph":{"skipped":false,"success":true,"msg_state_used":false,"account_activated":false,"gas_fees":"5138000","gas_used":"12845","gas_limit":"247484","mode":0,"exit_code":0,"vm_steps":274,"vm_init_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","vm_final_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"action":{"success":true,"valid":true,"no_funds":false,"status_change":"unchanged","total_fwd_fees":"1708400","total_action_fees":"1406531","result_code":0,"tot_actions":2,"spec_actions":0,"skipped_actions":0,"msgs_created":2,"action_list_hash":"hBjjQRhmPzm+RKgy6U+Ege0Hb0UxD5cNxn2hErwF/To=","tot_msg_size":{"cells":"7","bits":"3110"}}},"block_ref":{"workchain":0,"shard":"8000000000000000","seqno":34903585},"in_msg":{"hash":"59r5FWJBKUv8C7E2szCKDhjdsz0t9hLJM5OiFHToemc=","source":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","destination":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","value":"98993600","value_extra_currencies":{},"fwd_fee":"670939","ihr_fee":"0","created_lt":"36582626000002","created_at":"1751972976","opcode":"0x00000009","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"o7V4cZZJdfDYiGUOySLXQiP8zq9cSASvIlmbO/ucJzI=","body":"te6cckEBBAEApwADCAAAAAkBAgMAHGF2YWxhbmNoZS1mdWppAFQweGQ3MDY3QWUzQzM1OWU4Mzc4OTBiMjhCN0JEMGQyMDg0Q2ZEZjQ5YjUAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABNIZWxsbyBmcm9tIFJlbGF5ZXIhAAAAAAAAAAAAAAAAAGu4UHQ=","decoded":null},"init_state":null},"out_msgs":[{"hash":"WsQVGIoOXjS+BqJ46ebFGmzBUNGOY3t2DbZ1/EXK9h4=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":null,"value":null,"value_extra_currencies":null,"fwd_fee":null,"ihr_fee":null,"created_lt":"36582626000004","created_at":"1751972976","opcode":"0x8011315a","ihr_disabled":null,"bounce":null,"bounced":null,"import_fee":null,"message_content":{"hash":"laYhaSZO6QjQmRsJsn02MK8hcwwIgxMIYX2oFcjFNdA=","body":"te6cckEBBAEA5QADg4ARMVongLPlR00q7UAhiDXkc2kPeKq9V9c0sSm9YiUyZhXUykhs4AH2lBVEFjqex7VaPbPTvuLH5GEs5sIeXm+pcAECAwAcYXZhbGFuY2hlLWZ1amkAVDB4ZDcwNjdBZTNDMzU5ZTgzNzg5MGIyOEI3QkQwZDIwODRDZkRmNDliNQDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE0hlbGxvIGZyb20gUmVsYXllciEAAAAAAAAAAAAAAAAALSbhEA==","decoded":null},"init_state":null},{"hash":"5+pjUx9a/8fmExUlLPQKUWSf+p+/HGhbuiL6Trhuufw=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","value":"93402800","value_extra_currencies":{},"fwd_fee":"301869","ihr_fee":"0","created_lt":"36582626000005","created_at":"1751972976","opcode":"0x00000018","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"qvrlOoIcMk+4fXd5wBBiFUGFVRoCDCkhuAdj+PADXBE=","body":"te6cckEBAQEABgAACAAAABhDnyiV","decoded":null},"init_state":null}],"account_state_before":{"hash":"posCwcSHfOabFTEJpZf3DjjrwdCa0yhl9DX9LTojxY4=","balance":"2717267789","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"account_state_after":{"hash":"4OBdR8k83rjRSwwreZI6a8TmlsuKN5MrCbM/6B+8bFw=","balance":"2715939331","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"emulated":false}]}"#;
        let example_gateway =
            TonAddress::from_base64_url("kQAAGUqtjkIr7fQ_7nRtbZKdNp26slRopp1RNwbqaXi2OnXH")
                .unwrap();

        let log = extract_body(&example_gateway, rpc_return_text);
        assert!(log.is_err());
    }

    #[test]
    fn should_reject_invalid_call_contract_field_transactions_missing() {
        let rpc_return_text = r#"{"tx":[{"account":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","hash":"L/DSNQ43lWUDdga8h4ci8hVp+nVS6/BxEF7KrAO0yTo=","lt":"36582626000003","now":1751972976,"mc_block_seqno":33013054,"trace_id":"6h4rXxxaXBcwgFnNiyyzXolMBo6wDeqiW2+LIq8feHE=","prev_trans_hash":"BoNe1HOkg+5k8XGGuY5iRcuz8Nwkc5rxT7NuM/vDP/E=","prev_trans_lt":"36552848000003","orig_status":"active","end_status":"active","total_fees":"6617389","total_fees_extra_currencies":{},"description":{"type":"ord","aborted":false,"destroyed":false,"credit_first":false,"storage_ph":{"storage_fees_collected":"72858","status_change":"unchanged"},"credit_ph":{"credit":"98993600"},"compute_ph":{"skipped":false,"success":true,"msg_state_used":false,"account_activated":false,"gas_fees":"5138000","gas_used":"12845","gas_limit":"247484","mode":0,"exit_code":0,"vm_steps":274,"vm_init_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","vm_final_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"action":{"success":true,"valid":true,"no_funds":false,"status_change":"unchanged","total_fwd_fees":"1708400","total_action_fees":"1406531","result_code":0,"tot_actions":2,"spec_actions":0,"skipped_actions":0,"msgs_created":2,"action_list_hash":"hBjjQRhmPzm+RKgy6U+Ege0Hb0UxD5cNxn2hErwF/To=","tot_msg_size":{"cells":"7","bits":"3110"}}},"block_ref":{"workchain":0,"shard":"8000000000000000","seqno":34903585},"in_msg":{"hash":"59r5FWJBKUv8C7E2szCKDhjdsz0t9hLJM5OiFHToemc=","source":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","destination":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","value":"98993600","value_extra_currencies":{},"fwd_fee":"670939","ihr_fee":"0","created_lt":"36582626000002","created_at":"1751972976","opcode":"0x00000009","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"o7V4cZZJdfDYiGUOySLXQiP8zq9cSASvIlmbO/ucJzI=","body":"te6cckEBBAEApwADCAAAAAkBAgMAHGF2YWxhbmNoZS1mdWppAFQweGQ3MDY3QWUzQzM1OWU4Mzc4OTBiMjhCN0JEMGQyMDg0Q2ZEZjQ5YjUAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABNIZWxsbyBmcm9tIFJlbGF5ZXIhAAAAAAAAAAAAAAAAAGu4UHQ=","decoded":null},"init_state":null},"out_msgs":[{"hash":"WsQVGIoOXjS+BqJ46ebFGmzBUNGOY3t2DbZ1/EXK9h4=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":null,"value":null,"value_extra_currencies":null,"fwd_fee":null,"ihr_fee":null,"created_lt":"36582626000004","created_at":"1751972976","opcode":"0x8011315a","ihr_disabled":null,"bounce":null,"bounced":null,"import_fee":null,"message_content":{"hash":"laYhaSZO6QjQmRsJsn02MK8hcwwIgxMIYX2oFcjFNdA=","body":"te6cckEBBAEA5QADg4ARMVongLPlR00q7UAhiDXkc2kPeKq9V9c0sSm9YiUyZhXUykhs4AH2lBVEFjqex7VaPbPTvuLH5GEs5sIeXm+pcAECAwAcYXZhbGFuY2hlLWZ1amkAVDB4ZDcwNjdBZTNDMzU5ZTgzNzg5MGIyOEI3QkQwZDIwODRDZkRmNDliNQDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE0hlbGxvIGZyb20gUmVsYXllciEAAAAAAAAAAAAAAAAALSbhEA==","decoded":null},"init_state":null},{"hash":"5+pjUx9a/8fmExUlLPQKUWSf+p+/HGhbuiL6Trhuufw=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","value":"93402800","value_extra_currencies":{},"fwd_fee":"301869","ihr_fee":"0","created_lt":"36582626000005","created_at":"1751972976","opcode":"0x00000018","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"qvrlOoIcMk+4fXd5wBBiFUGFVRoCDCkhuAdj+PADXBE=","body":"te6cckEBAQEABgAACAAAABhDnyiV","decoded":null},"init_state":null}],"account_state_before":{"hash":"posCwcSHfOabFTEJpZf3DjjrwdCa0yhl9DX9LTojxY4=","balance":"2717267789","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"account_state_after":{"hash":"4OBdR8k83rjRSwwreZI6a8TmlsuKN5MrCbM/6B+8bFw=","balance":"2715939331","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"emulated":false}]}"#;
        let example_gateway =
            TonAddress::from_base64_url("kQAAGUqtjkIr7fQ_7nRtbZKdNp26slRopp1RNwbqaXi2OnXH")
                .unwrap();

        let log = extract_body(&example_gateway, rpc_return_text);
        assert!(log.is_err());
    }

    #[test]
    fn should_reject_invalid_call_contract_invalid_opcode() {
        // notice "opcode" is "invalid_opcode"
        let rpc_return_text = r#"{"transactions":[{"account":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","hash":"L/DSNQ43lWUDdga8h4ci8hVp+nVS6/BxEF7KrAO0yTo=","lt":"36582626000003","now":1751972976,"mc_block_seqno":33013054,"trace_id":"6h4rXxxaXBcwgFnNiyyzXolMBo6wDeqiW2+LIq8feHE=","prev_trans_hash":"BoNe1HOkg+5k8XGGuY5iRcuz8Nwkc5rxT7NuM/vDP/E=","prev_trans_lt":"36552848000003","orig_status":"active","end_status":"active","total_fees":"6617389","total_fees_extra_currencies":{},"description":{"type":"ord","aborted":false,"destroyed":false,"credit_first":false,"storage_ph":{"storage_fees_collected":"72858","status_change":"unchanged"},"credit_ph":{"credit":"98993600"},"compute_ph":{"skipped":false,"success":true,"msg_state_used":false,"account_activated":false,"gas_fees":"5138000","gas_used":"12845","gas_limit":"247484","mode":0,"exit_code":0,"vm_steps":274,"vm_init_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","vm_final_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"action":{"success":true,"valid":true,"no_funds":false,"status_change":"unchanged","total_fwd_fees":"1708400","total_action_fees":"1406531","result_code":0,"tot_actions":2,"spec_actions":0,"skipped_actions":0,"msgs_created":2,"action_list_hash":"hBjjQRhmPzm+RKgy6U+Ege0Hb0UxD5cNxn2hErwF/To=","tot_msg_size":{"cells":"7","bits":"3110"}}},"block_ref":{"workchain":0,"shard":"8000000000000000","seqno":34903585},"in_msg":{"hash":"59r5FWJBKUv8C7E2szCKDhjdsz0t9hLJM5OiFHToemc=","source":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","destination":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","value":"98993600","value_extra_currencies":{},"fwd_fee":"670939","ihr_fee":"0","created_lt":"36582626000002","created_at":"1751972976","opcode":"invalid_opcode","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"o7V4cZZJdfDYiGUOySLXQiP8zq9cSASvIlmbO/ucJzI=","body":"te6cckEBBAEApwADCAAAAAkBAgMAHGF2YWxhbmNoZS1mdWppAFQweGQ3MDY3QWUzQzM1OWU4Mzc4OTBiMjhCN0JEMGQyMDg0Q2ZEZjQ5YjUAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABNIZWxsbyBmcm9tIFJlbGF5ZXIhAAAAAAAAAAAAAAAAAGu4UHQ=","decoded":null},"init_state":null},"out_msgs":[{"hash":"WsQVGIoOXjS+BqJ46ebFGmzBUNGOY3t2DbZ1/EXK9h4=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":null,"value":null,"value_extra_currencies":null,"fwd_fee":null,"ihr_fee":null,"created_lt":"36582626000004","created_at":"1751972976","opcode":"0x8011315a","ihr_disabled":null,"bounce":null,"bounced":null,"import_fee":null,"message_content":{"hash":"laYhaSZO6QjQmRsJsn02MK8hcwwIgxMIYX2oFcjFNdA=","body":"invalid_body![+==","decoded":null},"init_state":null},{"hash":"5+pjUx9a/8fmExUlLPQKUWSf+p+/HGhbuiL6Trhuufw=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","value":"93402800","value_extra_currencies":{},"fwd_fee":"301869","ihr_fee":"0","created_lt":"36582626000005","created_at":"1751972976","opcode":"0x00000018","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"qvrlOoIcMk+4fXd5wBBiFUGFVRoCDCkhuAdj+PADXBE=","body":"te6cckEBAQEABgAACAAAABhDnyiV","decoded":null},"init_state":null}],"account_state_before":{"hash":"posCwcSHfOabFTEJpZf3DjjrwdCa0yhl9DX9LTojxY4=","balance":"2717267789","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"account_state_after":{"hash":"4OBdR8k83rjRSwwreZI6a8TmlsuKN5MrCbM/6B+8bFw=","balance":"2715939331","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"emulated":false}]}"#;
        let example_gateway =
            TonAddress::from_base64_url("kQAAGUqtjkIr7fQ_7nRtbZKdNp26slRopp1RNwbqaXi2OnXH")
                .unwrap();

        let log = extract_body(&example_gateway, rpc_return_text);
        assert!(log.is_err());
    }

    #[test]
    fn should_reject_invalid_call_contract_unparsable_contract() {
        // notice the "account" field that contains an unparsable contract
        let rpc_return_text = r#"{"transactions":[{"account":"not_a_contract_address","hash":"L/DSNQ43lWUDdga8h4ci8hVp+nVS6/BxEF7KrAO0yTo=","lt":"36582626000003","now":1751972976,"mc_block_seqno":33013054,"trace_id":"6h4rXxxaXBcwgFnNiyyzXolMBo6wDeqiW2+LIq8feHE=","prev_trans_hash":"BoNe1HOkg+5k8XGGuY5iRcuz8Nwkc5rxT7NuM/vDP/E=","prev_trans_lt":"36552848000003","orig_status":"active","end_status":"active","total_fees":"6617389","total_fees_extra_currencies":{},"description":{"type":"ord","aborted":false,"destroyed":false,"credit_first":false,"storage_ph":{"storage_fees_collected":"72858","status_change":"unchanged"},"credit_ph":{"credit":"98993600"},"compute_ph":{"skipped":false,"success":true,"msg_state_used":false,"account_activated":false,"gas_fees":"5138000","gas_used":"12845","gas_limit":"247484","mode":0,"exit_code":0,"vm_steps":274,"vm_init_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","vm_final_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"action":{"success":true,"valid":true,"no_funds":false,"status_change":"unchanged","total_fwd_fees":"1708400","total_action_fees":"1406531","result_code":0,"tot_actions":2,"spec_actions":0,"skipped_actions":0,"msgs_created":2,"action_list_hash":"hBjjQRhmPzm+RKgy6U+Ege0Hb0UxD5cNxn2hErwF/To=","tot_msg_size":{"cells":"7","bits":"3110"}}},"block_ref":{"workchain":0,"shard":"8000000000000000","seqno":34903585},"in_msg":{"hash":"59r5FWJBKUv8C7E2szCKDhjdsz0t9hLJM5OiFHToemc=","source":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","destination":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","value":"98993600","value_extra_currencies":{},"fwd_fee":"670939","ihr_fee":"0","created_lt":"36582626000002","created_at":"1751972976","opcode":"0x00000009","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"o7V4cZZJdfDYiGUOySLXQiP8zq9cSASvIlmbO/ucJzI=","body":"te6cckEBBAEApwADCAAAAAkBAgMAHGF2YWxhbmNoZS1mdWppAFQweGQ3MDY3QWUzQzM1OWU4Mzc4OTBiMjhCN0JEMGQyMDg0Q2ZEZjQ5YjUAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABNIZWxsbyBmcm9tIFJlbGF5ZXIhAAAAAAAAAAAAAAAAAGu4UHQ=","decoded":null},"init_state":null},"out_msgs":[{"hash":"WsQVGIoOXjS+BqJ46ebFGmzBUNGOY3t2DbZ1/EXK9h4=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":null,"value":null,"value_extra_currencies":null,"fwd_fee":null,"ihr_fee":null,"created_lt":"36582626000004","created_at":"1751972976","opcode":"0x8011315a","ihr_disabled":null,"bounce":null,"bounced":null,"import_fee":null,"message_content":{"hash":"laYhaSZO6QjQmRsJsn02MK8hcwwIgxMIYX2oFcjFNdA=","body":"te6cckEBBAEA5QADg4ARMVongLPlR00q7UAhiDXkc2kPeKq9V9c0sSm9YiUyZhXUykhs4AH2lBVEFjqex7VaPbPTvuLH5GEs5sIeXm+pcAECAwAcYXZhbGFuY2hlLWZ1amkAVDB4ZDcwNjdBZTNDMzU5ZTgzNzg5MGIyOEI3QkQwZDIwODRDZkRmNDliNQDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE0hlbGxvIGZyb20gUmVsYXllciEAAAAAAAAAAAAAAAAALSbhEA==","decoded":null},"init_state":null},{"hash":"5+pjUx9a/8fmExUlLPQKUWSf+p+/HGhbuiL6Trhuufw=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","value":"93402800","value_extra_currencies":{},"fwd_fee":"301869","ihr_fee":"0","created_lt":"36582626000005","created_at":"1751972976","opcode":"0x00000018","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"qvrlOoIcMk+4fXd5wBBiFUGFVRoCDCkhuAdj+PADXBE=","body":"te6cckEBAQEABgAACAAAABhDnyiV","decoded":null},"init_state":null}],"account_state_before":{"hash":"posCwcSHfOabFTEJpZf3DjjrwdCa0yhl9DX9LTojxY4=","balance":"2717267789","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"account_state_after":{"hash":"4OBdR8k83rjRSwwreZI6a8TmlsuKN5MrCbM/6B+8bFw=","balance":"2715939331","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"emulated":false}]}"#;
        let example_gateway =
            TonAddress::from_base64_url("kQAAGUqtjkIr7fQ_7nRtbZKdNp26slRopp1RNwbqaXi2OnXH")
                .unwrap();

        let log = extract_body(&example_gateway, rpc_return_text);
        assert!(log.is_err());
    }

    #[test]
    fn should_reject_invalid_call_contract_no_log_event() {
        // notice the "out_msgs" field has no entries
        let rpc_return_text = r#"{"transactions":[{"account":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","hash":"L/DSNQ43lWUDdga8h4ci8hVp+nVS6/BxEF7KrAO0yTo=","lt":"36582626000003","now":1751972976,"mc_block_seqno":33013054,"trace_id":"6h4rXxxaXBcwgFnNiyyzXolMBo6wDeqiW2+LIq8feHE=","prev_trans_hash":"BoNe1HOkg+5k8XGGuY5iRcuz8Nwkc5rxT7NuM/vDP/E=","prev_trans_lt":"36552848000003","orig_status":"active","end_status":"active","total_fees":"6617389","total_fees_extra_currencies":{},"description":{"type":"ord","aborted":false,"destroyed":false,"credit_first":false,"storage_ph":{"storage_fees_collected":"72858","status_change":"unchanged"},"credit_ph":{"credit":"98993600"},"compute_ph":{"skipped":false,"success":true,"msg_state_used":false,"account_activated":false,"gas_fees":"5138000","gas_used":"12845","gas_limit":"247484","mode":0,"exit_code":0,"vm_steps":274,"vm_init_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","vm_final_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"action":{"success":true,"valid":true,"no_funds":false,"status_change":"unchanged","total_fwd_fees":"1708400","total_action_fees":"1406531","result_code":0,"tot_actions":2,"spec_actions":0,"skipped_actions":0,"msgs_created":2,"action_list_hash":"hBjjQRhmPzm+RKgy6U+Ege0Hb0UxD5cNxn2hErwF/To=","tot_msg_size":{"cells":"7","bits":"3110"}}},"block_ref":{"workchain":0,"shard":"8000000000000000","seqno":34903585},"in_msg":{"hash":"59r5FWJBKUv8C7E2szCKDhjdsz0t9hLJM5OiFHToemc=","source":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","destination":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","value":"98993600","value_extra_currencies":{},"fwd_fee":"670939","ihr_fee":"0","created_lt":"36582626000002","created_at":"1751972976","opcode":"0x00000009","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"o7V4cZZJdfDYiGUOySLXQiP8zq9cSASvIlmbO/ucJzI=","body":"te6cckEBBAEApwADCAAAAAkBAgMAHGF2YWxhbmNoZS1mdWppAFQweGQ3MDY3QWUzQzM1OWU4Mzc4OTBiMjhCN0JEMGQyMDg0Q2ZEZjQ5YjUAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABNIZWxsbyBmcm9tIFJlbGF5ZXIhAAAAAAAAAAAAAAAAAGu4UHQ=","decoded":null},"init_state":null},"out_msgs":[],"account_state_before":{"hash":"posCwcSHfOabFTEJpZf3DjjrwdCa0yhl9DX9LTojxY4=","balance":"2717267789","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"account_state_after":{"hash":"4OBdR8k83rjRSwwreZI6a8TmlsuKN5MrCbM/6B+8bFw=","balance":"2715939331","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"emulated":false}]}"#;
        let example_gateway =
            TonAddress::from_base64_url("kQAAGUqtjkIr7fQ_7nRtbZKdNp26slRopp1RNwbqaXi2OnXH")
                .unwrap();

        let log = extract_body(&example_gateway, rpc_return_text);
        assert!(log.is_err());
    }

    #[test]
    fn should_reject_invalid_call_contract_invalid_event_body() {
        // notice the "out_msgs" body field contains non-base64 data
        let rpc_return_text = r#"{"transactions":[{"account":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","hash":"L/DSNQ43lWUDdga8h4ci8hVp+nVS6/BxEF7KrAO0yTo=","lt":"36582626000003","now":1751972976,"mc_block_seqno":33013054,"trace_id":"6h4rXxxaXBcwgFnNiyyzXolMBo6wDeqiW2+LIq8feHE=","prev_trans_hash":"BoNe1HOkg+5k8XGGuY5iRcuz8Nwkc5rxT7NuM/vDP/E=","prev_trans_lt":"36552848000003","orig_status":"active","end_status":"active","total_fees":"6617389","total_fees_extra_currencies":{},"description":{"type":"ord","aborted":false,"destroyed":false,"credit_first":false,"storage_ph":{"storage_fees_collected":"72858","status_change":"unchanged"},"credit_ph":{"credit":"98993600"},"compute_ph":{"skipped":false,"success":true,"msg_state_used":false,"account_activated":false,"gas_fees":"5138000","gas_used":"12845","gas_limit":"247484","mode":0,"exit_code":0,"vm_steps":274,"vm_init_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","vm_final_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"action":{"success":true,"valid":true,"no_funds":false,"status_change":"unchanged","total_fwd_fees":"1708400","total_action_fees":"1406531","result_code":0,"tot_actions":2,"spec_actions":0,"skipped_actions":0,"msgs_created":2,"action_list_hash":"hBjjQRhmPzm+RKgy6U+Ege0Hb0UxD5cNxn2hErwF/To=","tot_msg_size":{"cells":"7","bits":"3110"}}},"block_ref":{"workchain":0,"shard":"8000000000000000","seqno":34903585},"in_msg":{"hash":"59r5FWJBKUv8C7E2szCKDhjdsz0t9hLJM5OiFHToemc=","source":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","destination":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","value":"98993600","value_extra_currencies":{},"fwd_fee":"670939","ihr_fee":"0","created_lt":"36582626000002","created_at":"1751972976","opcode":"0x00000009","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"o7V4cZZJdfDYiGUOySLXQiP8zq9cSASvIlmbO/ucJzI=","body":"te6cckEBBAEApwADCAAAAAkBAgMAHGF2YWxhbmNoZS1mdWppAFQweGQ3MDY3QWUzQzM1OWU4Mzc4OTBiMjhCN0JEMGQyMDg0Q2ZEZjQ5YjUAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABNIZWxsbyBmcm9tIFJlbGF5ZXIhAAAAAAAAAAAAAAAAAGu4UHQ=","decoded":null},"init_state":null},"out_msgs":[{"hash":"WsQVGIoOXjS+BqJ46ebFGmzBUNGOY3t2DbZ1/EXK9h4=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":null,"value":null,"value_extra_currencies":null,"fwd_fee":null,"ihr_fee":null,"created_lt":"36582626000004","created_at":"1751972976","opcode":"0x8011315a","ihr_disabled":null,"bounce":null,"bounced":null,"import_fee":null,"message_content":{"hash":"laYhaSZO6QjQmRsJsn02MK8hcwwIgxMIYX2oFcjFNdA=","body":"=!§$","decoded":null},"init_state":null},{"hash":"5+pjUx9a/8fmExUlLPQKUWSf+p+/HGhbuiL6Trhuufw=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","value":"93402800","value_extra_currencies":{},"fwd_fee":"301869","ihr_fee":"0","created_lt":"36582626000005","created_at":"1751972976","opcode":"0x00000018","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"qvrlOoIcMk+4fXd5wBBiFUGFVRoCDCkhuAdj+PADXBE=","body":"te6cckEBAQEABgAACAAAABhDnyiV","decoded":null},"init_state":null}],"account_state_before":{"hash":"posCwcSHfOabFTEJpZf3DjjrwdCa0yhl9DX9LTojxY4=","balance":"2717267789","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"account_state_after":{"hash":"4OBdR8k83rjRSwwreZI6a8TmlsuKN5MrCbM/6B+8bFw=","balance":"2715939331","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"emulated":false}]}"#;
        let example_gateway =
            TonAddress::from_base64_url("kQAAGUqtjkIr7fQ_7nRtbZKdNp26slRopp1RNwbqaXi2OnXH")
                .unwrap();

        let log = extract_body(&example_gateway, rpc_return_text);
        assert!(log.is_err());
    }

    #[test]
    fn should_reject_invalid_call_contract_no_tx() {
        let rpc_return_text = r#"{"transactions":[]}"#;
        let example_gateway =
            TonAddress::from_base64_url("kQAAGUqtjkIr7fQ_7nRtbZKdNp26slRopp1RNwbqaXi2OnXH")
                .unwrap();

        let log = extract_body(&example_gateway, rpc_return_text);
        assert!(log.is_err());
    }

    #[test]
    fn should_parse_correct_signer_rotation() {
        let rpc_return_text = r#"{"transactions":[{"account":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","hash":"L/DSNQ43lWUDdga8h4ci8hVp+nVS6/BxEF7KrAO0yTo=","lt":"36582626000003","now":1751972976,"mc_block_seqno":33013054,"trace_id":"6h4rXxxaXBcwgFnNiyyzXolMBo6wDeqiW2+LIq8feHE=","prev_trans_hash":"BoNe1HOkg+5k8XGGuY5iRcuz8Nwkc5rxT7NuM/vDP/E=","prev_trans_lt":"36552848000003","orig_status":"active","end_status":"active","total_fees":"6617389","total_fees_extra_currencies":{},"description":{"type":"ord","aborted":false,"destroyed":false,"credit_first":false,"storage_ph":{"storage_fees_collected":"72858","status_change":"unchanged"},"credit_ph":{"credit":"98993600"},"compute_ph":{"skipped":false,"success":true,"msg_state_used":false,"account_activated":false,"gas_fees":"5138000","gas_used":"12845","gas_limit":"247484","mode":0,"exit_code":0,"vm_steps":274,"vm_init_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","vm_final_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"action":{"success":true,"valid":true,"no_funds":false,"status_change":"unchanged","total_fwd_fees":"1708400","total_action_fees":"1406531","result_code":0,"tot_actions":2,"spec_actions":0,"skipped_actions":0,"msgs_created":2,"action_list_hash":"hBjjQRhmPzm+RKgy6U+Ege0Hb0UxD5cNxn2hErwF/To=","tot_msg_size":{"cells":"7","bits":"3110"}}},"block_ref":{"workchain":0,"shard":"8000000000000000","seqno":34903585},"in_msg":{"hash":"59r5FWJBKUv8C7E2szCKDhjdsz0t9hLJM5OiFHToemc=","source":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","destination":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","value":"98993600","value_extra_currencies":{},"fwd_fee":"670939","ihr_fee":"0","created_lt":"36582626000002","created_at":"1751972976","opcode":"0x0000002a","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"o7V4cZZJdfDYiGUOySLXQiP8zq9cSASvIlmbO/ucJzI=","body":"removed","decoded":null},"init_state":null},"out_msgs":[{"hash":"WsQVGIoOXjS+BqJ46ebFGmzBUNGOY3t2DbZ1/EXK9h4=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":null,"value":null,"value_extra_currencies":null,"fwd_fee":null,"ihr_fee":null,"created_lt":"36582626000004","created_at":"1751972976","opcode":"0x8011315a","ihr_disabled":null,"bounce":null,"bounced":null,"import_fee":null,"message_content":{"hash":"laYhaSZO6QjQmRsJsn02MK8hcwwIgxMIYX2oFcjFNdA=","body":"te6cckECCAEAAg8AAWGAAAAAAAAAAAAAAAAAAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAQICzgIFAgEgAwQA4QDoQe/884Qvh1w3RjnS8CZZ+TWMJulDV8d3IZkElUxuAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAOEQ83AI9ItX54QfRoGk0V9NdHRDrfSHHIRkvVvXeQGZdMAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAIBIAYHAOESB7edy2hV4XJ5ZoIYgG4w/nDBxKeP8bX80qk3+1YFOUAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIADhHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZkAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACDebNbp","decoded":null},"init_state":null},{"hash":"5+pjUx9a/8fmExUlLPQKUWSf+p+/HGhbuiL6Trhuufw=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","value":"93402800","value_extra_currencies":{},"fwd_fee":"301869","ihr_fee":"0","created_lt":"36582626000005","created_at":"1751972976","opcode":"0x00000018","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"qvrlOoIcMk+4fXd5wBBiFUGFVRoCDCkhuAdj+PADXBE=","body":"te6cckEBAQEABgAACAAAABhDnyiV","decoded":null},"init_state":null}],"account_state_before":{"hash":"posCwcSHfOabFTEJpZf3DjjrwdCa0yhl9DX9LTojxY4=","balance":"2717267789","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"account_state_after":{"hash":"4OBdR8k83rjRSwwreZI6a8TmlsuKN5MrCbM/6B+8bFw=","balance":"2715939331","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"emulated":false}]}"#;
        let example_gateway =
            TonAddress::from_base64_url("kQAAGUqtjkIr7fQ_7nRtbZKdNp26slRopp1RNwbqaXi2OnXH")
                .unwrap();

        let log = extract_body(&example_gateway, rpc_return_text);
        assert!(log.is_ok());
    }

    #[test]
    fn should_reject_incorrect_signer_rotation_wrong_contract() {
        // notice the "account" field starting with "9"
        let rpc_return_text = r#"{"transactions":[{"account":"9:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","hash":"L/DSNQ43lWUDdga8h4ci8hVp+nVS6/BxEF7KrAO0yTo=","lt":"36582626000003","now":1751972976,"mc_block_seqno":33013054,"trace_id":"6h4rXxxaXBcwgFnNiyyzXolMBo6wDeqiW2+LIq8feHE=","prev_trans_hash":"BoNe1HOkg+5k8XGGuY5iRcuz8Nwkc5rxT7NuM/vDP/E=","prev_trans_lt":"36552848000003","orig_status":"active","end_status":"active","total_fees":"6617389","total_fees_extra_currencies":{},"description":{"type":"ord","aborted":false,"destroyed":false,"credit_first":false,"storage_ph":{"storage_fees_collected":"72858","status_change":"unchanged"},"credit_ph":{"credit":"98993600"},"compute_ph":{"skipped":false,"success":true,"msg_state_used":false,"account_activated":false,"gas_fees":"5138000","gas_used":"12845","gas_limit":"247484","mode":0,"exit_code":0,"vm_steps":274,"vm_init_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","vm_final_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"action":{"success":true,"valid":true,"no_funds":false,"status_change":"unchanged","total_fwd_fees":"1708400","total_action_fees":"1406531","result_code":0,"tot_actions":2,"spec_actions":0,"skipped_actions":0,"msgs_created":2,"action_list_hash":"hBjjQRhmPzm+RKgy6U+Ege0Hb0UxD5cNxn2hErwF/To=","tot_msg_size":{"cells":"7","bits":"3110"}}},"block_ref":{"workchain":0,"shard":"8000000000000000","seqno":34903585},"in_msg":{"hash":"59r5FWJBKUv8C7E2szCKDhjdsz0t9hLJM5OiFHToemc=","source":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","destination":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","value":"98993600","value_extra_currencies":{},"fwd_fee":"670939","ihr_fee":"0","created_lt":"36582626000002","created_at":"1751972976","opcode":"0x0000002a","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"o7V4cZZJdfDYiGUOySLXQiP8zq9cSASvIlmbO/ucJzI=","body":"removed","decoded":null},"init_state":null},"out_msgs":[{"hash":"WsQVGIoOXjS+BqJ46ebFGmzBUNGOY3t2DbZ1/EXK9h4=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":null,"value":null,"value_extra_currencies":null,"fwd_fee":null,"ihr_fee":null,"created_lt":"36582626000004","created_at":"1751972976","opcode":"0x8011315a","ihr_disabled":null,"bounce":null,"bounced":null,"import_fee":null,"message_content":{"hash":"laYhaSZO6QjQmRsJsn02MK8hcwwIgxMIYX2oFcjFNdA=","body":"te6cckECCAEAAg8AAWGAAAAAAAAAAAAAAAAAAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAQICzgIFAgEgAwQA4QDoQe/884Qvh1w3RjnS8CZZ+TWMJulDV8d3IZkElUxuAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAOEQ83AI9ItX54QfRoGk0V9NdHRDrfSHHIRkvVvXeQGZdMAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAIBIAYHAOESB7edy2hV4XJ5ZoIYgG4w/nDBxKeP8bX80qk3+1YFOUAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIADhHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZkAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACDebNbp","decoded":null},"init_state":null},{"hash":"5+pjUx9a/8fmExUlLPQKUWSf+p+/HGhbuiL6Trhuufw=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","value":"93402800","value_extra_currencies":{},"fwd_fee":"301869","ihr_fee":"0","created_lt":"36582626000005","created_at":"1751972976","opcode":"0x00000018","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"qvrlOoIcMk+4fXd5wBBiFUGFVRoCDCkhuAdj+PADXBE=","body":"te6cckEBAQEABgAACAAAABhDnyiV","decoded":null},"init_state":null}],"account_state_before":{"hash":"posCwcSHfOabFTEJpZf3DjjrwdCa0yhl9DX9LTojxY4=","balance":"2717267789","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"account_state_after":{"hash":"4OBdR8k83rjRSwwreZI6a8TmlsuKN5MrCbM/6B+8bFw=","balance":"2715939331","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"emulated":false}]}"#;

        let example_gateway =
            TonAddress::from_base64_url("kQAAGUqtjkIr7fQ_7nRtbZKdNp26slRopp1RNwbqaXi2OnXH")
                .unwrap();

        let log = extract_body(&example_gateway, rpc_return_text);
        assert!(log.is_err());
    }
}
