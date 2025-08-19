use std::str::FromStr;

use axelar_solana_gateway::processor::GatewayEvent;
use axelar_solana_gateway::state::GatewayConfig;
use axelar_solana_gateway::BytemuckedPda;
use axelar_wasm_std::msg_id::Base58SolanaTxSignatureAndEventIndex;
use axelar_wasm_std::voting::Vote;
use router_api::ChainName;
use serde::{Deserialize, Deserializer};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_transaction_status::option_serializer::OptionSerializer;
use solana_transaction_status::UiTransactionStatusMeta;
use tracing::{error, warn};

use crate::monitoring;
use crate::monitoring::metrics::Msg;

pub mod msg_verifier;
pub mod verifier_set_verifier;

pub struct Client {
    client: RpcClient,
    monitoring_client: monitoring::Client,
    chain_name: ChainName,
}

impl Client {
    pub fn new(
        client: RpcClient,
        monitoring_client: monitoring::Client,
        chain_name: ChainName,
    ) -> Self {
        Self {
            client,
            monitoring_client,
            chain_name,
        }
    }
}

#[async_trait::async_trait]
pub trait SolanaRpcClientProxy: Send + Sync + 'static {
    async fn tx(&self, signature: &Signature) -> Option<UiTransactionStatusMeta>;
    async fn domain_separator(&self) -> Option<[u8; 32]>;
}

#[async_trait::async_trait]
impl SolanaRpcClientProxy for Client {
    async fn tx(&self, signature: &Signature) -> Option<UiTransactionStatusMeta> {
        let res = self
            .client
            .get_transaction(
                signature,
                solana_transaction_status::UiTransactionEncoding::Base58,
            )
            .await;

        self.monitoring_client
            .metrics()
            .record_metric(Msg::RpcCall {
                chain_name: self.chain_name.clone(),
                success: res.is_ok(),
            });

        res.map(|tx_data| tx_data.transaction.meta).ok().flatten()
    }

    async fn domain_separator(&self) -> Option<[u8; 32]> {
        let (gateway_root_pda, ..) = axelar_solana_gateway::get_gateway_root_config_pda();

        let res = self.client.get_account(&gateway_root_pda).await;

        self.monitoring_client
            .metrics()
            .record_metric(Msg::RpcCall {
                chain_name: self.chain_name.clone(),
                success: res.is_ok(),
            });

        let config_data = res.ok()?.data;

        let config = *GatewayConfig::read(&config_data)?;
        let domain_separator = config.domain_separator;
        Some(domain_separator)
    }
}

pub fn deserialize_pubkey<'de, D>(deserializer: D) -> Result<Pubkey, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Pubkey::from_str(&s).map_err(serde::de::Error::custom)
}

pub fn verify<F>(
    tx: (&Signature, &UiTransactionStatusMeta),
    message_id: &Base58SolanaTxSignatureAndEventIndex,
    events_are_equal: F,
) -> Vote
where
    F: Fn(&GatewayEvent) -> bool,
{
    // message id signatures must match
    let (signature, tx) = tx;
    if signature.as_ref() != message_id.raw_signature {
        error!("signatures don't match");
        return Vote::NotFound;
    }

    // the tx must be successful
    if tx.err.is_some() {
        error!("Transaction failed");
        return Vote::FailedOnChain;
    }

    // the event idx cannot be larger than usize. However, a valid event will never have an index larger than usize,
    // as the native arch will be 64 bit, and the event index is a u64.
    let desired_event_idx: usize = match message_id.event_index.try_into() {
        Ok(idx) => idx,
        Err(_) => {
            error!("Cannot fit event index into system usize. Index was: {}, but current system usize is: {}", message_id.event_index, usize::MAX);
            return Vote::NotFound;
        }
    };

    // logs must be attached to the TX
    let logs = match tx.log_messages.as_ref() {
        OptionSerializer::Some(logs) => logs,
        _ => {
            error!("Logs not attached to the transaction object");
            return Vote::NotFound;
        }
    };

    // Check in the logs in a backward way the invocation comes from the gateway
    let log = match event_comes_from_gateway(logs, desired_event_idx) {
        Ok(log) => log,
        Err(err) => {
            error!("Cannot find the gateway log: {}", err);
            return Vote::NotFound;
        }
    };

    // Second ensure we can parse the event
    let event = match gateway_event_stack::parse_gateway_logs(&log) {
        Ok(ev) => ev,
        Err(err) => {
            error!("Cannot parse the gateway log: {}", err);
            return Vote::NotFound;
        }
    };

    if events_are_equal(&event) {
        Vote::SucceededOnChain
    } else {
        warn!(?event, "event was found, but contents were not equal");
        Vote::NotFound
    }
}

// Constants for parsing Solana program logs
const PROGRAM_STR_INDEX: usize = 0;
const PROGRAM_ID_INDEX: usize = 1;
const INVOKE_STR_INDEX: usize = 2;
const INVOKE_RESULT_INDEX: usize = 2;
const CALL_DEPTH_STR_INDEX: usize = 3;
const INVOKE_LOG_PARTS_COUNT: usize = 4;
const INVOKE_RESULT_LOG_PARTS_COUNT: usize = 3;
const PROGRAM_STR: &str = "Program";
const INVOKE_STR: &str = "invoke";
const SUCCESS_STR: &str = "success";
const FAILURE_STR: &str = "failed";
const PROGRAM_DATA_STR: &str = "Program data";
const PROGRAM_LOG_STR: &str = "Program log";

fn try_extract_event_data(
    logs: &[String],
    desired_event_idx: usize,
) -> Result<&str, Box<dyn std::error::Error>> {
    if desired_event_idx >= logs.len() {
        return Err("Event index out of bounds".into());
    }

    let data_log = &logs[desired_event_idx];
    if !data_log.starts_with(PROGRAM_DATA_STR) {
        return Err("Invalid event index".into());
    }

    Ok(data_log)
}

fn is_invoke_log(log: &str) -> bool {
    log.starts_with(PROGRAM_STR)
        && log.contains(INVOKE_STR)
        && !log.starts_with(PROGRAM_LOG_STR)
        && !log.starts_with(PROGRAM_DATA_STR)
}

fn is_completion_log(log: &str) -> bool {
    (log.contains(SUCCESS_STR) || log.contains(FAILURE_STR))
        && log.starts_with(PROGRAM_STR)
        && !log.starts_with(PROGRAM_LOG_STR)
        && !log.starts_with(PROGRAM_DATA_STR)
}

fn parse_invoke_log(log: &str) -> Result<(String, usize), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = log.split_whitespace().collect();
    if parts.len() != INVOKE_LOG_PARTS_COUNT
        || parts[PROGRAM_STR_INDEX] != PROGRAM_STR
        || parts[INVOKE_STR_INDEX] != INVOKE_STR
    {
        return Err("Invalid invoke log format".into());
    }

    let program_id = parts[PROGRAM_ID_INDEX].to_string();
    let depth_str = parts[CALL_DEPTH_STR_INDEX];

    if !depth_str.starts_with('[') || !depth_str.ends_with(']') {
        return Err("Invalid depth format".into());
    }

    let depth = depth_str[1..depth_str.len().saturating_sub(1)]
        .parse::<usize>()
        .map_err(|_err| "Failed to parse depth")?;

    Ok((program_id, depth))
}

fn parse_completion_log(log: &str) -> Result<String, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = log.split_whitespace().collect();
    if parts.len() < INVOKE_RESULT_LOG_PARTS_COUNT
        || parts[PROGRAM_STR_INDEX] != PROGRAM_STR
        || (!parts[INVOKE_RESULT_INDEX].starts_with(SUCCESS_STR)
            && !parts[INVOKE_RESULT_INDEX].starts_with(FAILURE_STR))
    {
        return Err("Invalid completion log format".into());
    }

    Ok(parts[PROGRAM_ID_INDEX].to_string())
}

fn handle_invoke_log(
    log: &str,
    execution_stack: &mut Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (program_id, depth) = parse_invoke_log(log)?;

    if depth != execution_stack.len().saturating_add(1) {
        return Err("Call stack depth mismatch".into());
    }

    execution_stack.push(program_id);
    Ok(())
}

fn handle_completion_log(
    log: &str,
    execution_stack: &mut Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let program_id = parse_completion_log(log)?;

    // Enforce LIFO completion - program must be at top of stack
    match execution_stack.last() {
        Some(top_program) if *top_program == program_id => {
            execution_stack.pop();
            Ok(())
        }
        Some(top_program) => {
            Err(format!(
                "Malformed logs: expected {top_program} to complete, but {program_id} completed instead"
            ).into())
        }
        None => {
            Err(format!(
                "Malformed logs: program {program_id} completed but execution stack is empty"
            ).into())
        }
    }
}

fn validate_gateway_context(
    execution_context: Option<&String>,
    gateway_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match execution_context {
        Some(program_id) if *program_id == gateway_id => Ok(()),
        Some(_) => Err("Log was emitted by a different program".into()),
        None => Err("Log was not emitted during any program execution".into()),
    }
}

// Check in the logs if the invocation comes from the gateway program, returning the data log if
// the event comes from the gateway.
//
// Example logs input (indexes are just for reference):
//
// 1. Program gtwLjHAsfKAR6GWB4hzTUAA1w4SDdFMKamtGA5ttMEe invoke [1]
// 2. Program log: Instruction: Call Contract",
// 3. Program data: Y2FsbCBjb250cmFjdF9fXw== 6NGe5cm7PkXHz/g8V2VdRg0nU0l7R48x8lll4s0Clz0= xtlu5J3pLn7c4BhqnNSrP1wDZK/pQOJVCYbk6sroJhY= ZXRoZXJldW0= MHgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA2YzIwNjAzYzdiODc2NjgyYzEyMTczYmRlZjlhMWRjYTUyOGYxNGZk 8J+QqvCfkKrwn5Cq8J+Qqg==",
// 4. Program gtwLjHAsfKAR6GWB4hzTUAA1w4SDdFMKamtGA5ttMEe success"
//
// In the above log example, this function would return the data log at 3, if and only if the event comes from the gateway,
// which is determined by scanning log lines while keeping track of the CPI call stack.
fn event_comes_from_gateway(
    logs: &[String],
    desired_event_idx: usize,
) -> Result<&str, Box<dyn std::error::Error>> {
    let solana_gateway_id = axelar_solana_gateway::id().to_string();

    let data_log = try_extract_event_data(logs, desired_event_idx)?;
    let logs_slice = &logs[0..=desired_event_idx];

    let mut execution_stack: Vec<String> = Vec::new();
    let mut data_log_program_context = None;

    for (idx, log) in logs_slice.iter().enumerate() {
        if is_invoke_log(log) {
            handle_invoke_log(log, &mut execution_stack)?;
        } else if is_completion_log(log) {
            handle_completion_log(log, &mut execution_stack)?;
        }

        // Capture execution context at target index
        if idx == desired_event_idx {
            data_log_program_context = execution_stack.last();
            break;
        }
    }

    // Validate that data log was emitted during gateway execution
    validate_gateway_context(data_log_program_context, &solana_gateway_id)?;

    Ok(data_log)
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use router_api::ChainName;
    use solana_client::nonblocking::rpc_client::RpcClient;
    use solana_sdk::signature::Signature;

    use super::{event_comes_from_gateway, Client, SolanaRpcClientProxy};
    use crate::monitoring::metrics::Msg;
    use crate::monitoring::test_utils;

    #[tokio::test]
    async fn should_record_rpc_failure_metrics_successfully() {
        let (monitoring_client, mut receiver) = test_utils::monitoring_client();

        let client = Client::new(
            RpcClient::new("invalid_url".to_string()),
            monitoring_client,
            ChainName::from_str("solana").unwrap(),
        );

        let result = client.tx(&Signature::default()).await;
        assert!(result.is_none());

        let msg = receiver.recv().await.unwrap();
        assert_eq!(
            msg,
            Msg::RpcCall {
                chain_name: ChainName::from_str("solana").unwrap(),
                success: false,
            }
        );

        let result = client.domain_separator().await;
        assert!(result.is_none());

        let msg = receiver.recv().await.unwrap();
        assert_eq!(
            msg,
            Msg::RpcCall {
                chain_name: ChainName::from_str("solana").unwrap(),
                success: false,
            }
        );

        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn test_event_comes_from_gateway_vulnerability_malicious_log_spoofing() {
        let gateway_id = axelar_solana_gateway::id().to_string();
        let malicious_caller_id = "Ex1Ez6K83RB8uC3wqDSgYmXht3P8QFyQrEG38KiYsjPe";

        let malicious_logs = vec![
            format!("Program {} invoke [1]", malicious_caller_id), // 0 - Malicious caller program
            format!("Program {} invoke [2]", gateway_id),           // 1 - Gateway CPI program execution
            "Program log: Instruction: Call Contract".to_string(),  // 2
            "Program data: Y2FsbCBjb250cmFjdF9fXw== zz8lrJgsyTRqLrotzeb8viPM8JKO26TBWYArn/oewmk= Dv0Zw9e54rFy7Nfr2FlYwtKjsnR4Ae57XO5ZVXiqjCA= ZXRoZXJldW0= MHgxMjNhYmM= TXkgY3Jvc3MtY2hhaW4gbWVzc2FnZQ==".to_string(), // 3 - Real event data
            format!("Program {} consumed 4631 of 177598 compute units", gateway_id), // 4
            format!("Program {} success", gateway_id),              // 5 - Ending of Gateway Program
            "Program data: Y2FsbCBjb250cmFjdF9fXw== MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE= QUFBQUFBQUFBQUFBQUE= ZXRoZXJldW0= QnJpZGdlMXA1Z2hlWFV2SjZqR1dHZUNzZ1BLZ25FM1lnZEdLUlZDTVk5bw== QUFBQUFBQUFBQUFBQUE=".to_string(), // 6 - Malicious data
        ];

        let result_legitimate = event_comes_from_gateway(&malicious_logs, 3);
        assert!(
            result_legitimate.is_ok(),
            "Legitimate event should be accepted"
        );
        assert_eq!(
            result_legitimate.unwrap(),
            "Program data: Y2FsbCBjb250cmFjdF9fXw== zz8lrJgsyTRqLrotzeb8viPM8JKO26TBWYArn/oewmk= Dv0Zw9e54rFy7Nfr2FlYwtKjsnR4Ae57XO5ZVXiqjCA= ZXRoZXJldW0= MHgxMjNhYmM= TXkgY3Jvc3MtY2hhaW4gbWVzc2FnZQ=="
        );

        let result_malicious = event_comes_from_gateway(&malicious_logs, 6);

        match result_malicious {
            Ok(data) => {
                println!("Function returned malicious data: {}", data);
                panic!("Vulnerability exists! The function incorrectly accepted malicious log data at index 6");
            }
            Err(e) => {
                assert!(e
                    .to_string()
                    .contains("Log was emitted by a different program"));
            }
        }
    }

    #[test]
    fn test_event_comes_from_gateway_cross_cpi_frame_detection() {
        let gateway_id = axelar_solana_gateway::id().to_string();

        let logs_with_cpi_boundary = vec![
            "Program SomeOtherProgram invoke [1]".to_string(), // 0 - Different program
            format!("Program {} invoke [2]", gateway_id),      // 1 - Gateway as CPI call
            format!("Program {} success", gateway_id),         // 2 - Gateway success
            "Program SomeOtherProgram success".to_string(),    // 3 - Other program success
            "Program data: Malicious data outside gateway frame".to_string(), // 4 - Malicious data
        ];

        let result = event_comes_from_gateway(&logs_with_cpi_boundary, 4);

        assert!(
            result.is_err(),
            "Should reject data outside gateway execution frame"
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Log was not emitted during any program execution"));
    }

    #[test]
    fn test_event_comes_from_gateway_legitimate_case() {
        let gateway_id = axelar_solana_gateway::id().to_string();

        let legitimate_logs = vec![
            format!("Program {} invoke [1]", gateway_id), // 0 - Gateway program execution
            "Program log: Instruction: Call Contract".to_string(), // 1
            "Program data: Y2FsbCBjb250cmFjdF9fXw== validdata==".to_string(), // 2 - Event data
            format!("Program {} consumed 4631 compute units", gateway_id), // 3
            format!("Program {} success", gateway_id),    // 4
        ];

        let result = event_comes_from_gateway(&legitimate_logs, 2);
        assert!(result.is_ok(), "Legitimate gateway call should succeed");
        assert_eq!(
            result.unwrap(),
            "Program data: Y2FsbCBjb250cmFjdF9fXw== validdata=="
        );
    }

    #[test]
    fn test_event_comes_from_gateway_nested_calls() {
        let gateway_id = axelar_solana_gateway::id().to_string();
        let malicious_program = "MaliciousProgram123";

        let nested_logs = vec![
            format!("Program {} invoke [1]", malicious_program), // 0 - Outer malicious caller
            format!("Program {} invoke [2]", gateway_id),        // 1 - Outer gateway call (depth 2)
            "Program log: Instruction: Call Contract".to_string(), // 2
            format!("Program {} invoke [3]", gateway_id), // 3 - Nested gateway call (depth 3)
            "Program data: inner_call_data".to_string(), // 4 - Data from nested call (should succeed)
            format!("Program {} success", gateway_id),   // 5 - Nested call success (depth 3 ends)
            "Program data: outer_call_data".to_string(), // 6 - Data from outer call (should succeed)
            format!("Program {} success", gateway_id),   // 7 - Outer call success (depth 2 ends)
            format!("Program {} success", malicious_program), // 8 - Malicious program success (depth 1 ends)
            "Program data: Malicious data outside all frames".to_string(), // 9 - Should fail - outside all gateway frames
        ];

        // Access data from nested call (index 4) - should succeed
        let result_inner = event_comes_from_gateway(&nested_logs, 4);
        assert!(
            result_inner.is_ok(),
            "Should accept legitimate nested gateway data"
        );
        assert_eq!(result_inner.unwrap(), "Program data: inner_call_data");

        // Access data from outer call (index 6) - should succeed
        let result_outer = event_comes_from_gateway(&nested_logs, 6);
        assert!(
            result_outer.is_ok(),
            "Should accept legitimate outer gateway data"
        );
        assert_eq!(result_outer.unwrap(), "Program data: outer_call_data");

        // Try to access data outside all frames (index 9) - should fail
        let result_malicious = event_comes_from_gateway(&nested_logs, 9);
        assert!(
            result_malicious.is_err(),
            "Should reject data from outside all gateway execution frames"
        );
        assert!(result_malicious
            .unwrap_err()
            .to_string()
            .contains("Log was not emitted during any program execution"));
    }

    #[test]
    fn test_event_comes_from_gateway_complex_nested_scenario() {
        let gateway_id = axelar_solana_gateway::id().to_string();
        let program_a = "ProgramA";
        let program_b = "ProgramB";

        // Multiple programs making nested calls
        let complex_logs = vec![
            format!("Program {} invoke [1]", program_a), // 0 - Program A starts
            format!("Program {} invoke [2]", gateway_id), // 1 - Gateway called by A (depth 2)
            format!("Program {} invoke [3]", program_b), // 2 - Program B called by gateway (depth 3)
            format!("Program {} invoke [4]", gateway_id), // 3 - Gateway called by B (depth 4)
            "Program data: deepest_gateway_data".to_string(), // 4 - Data from deepest gateway
            format!("Program {} success", gateway_id),   // 5 - Deepest gateway success (depth 4)
            format!("Program {} success", program_b),    // 6 - Program B success (depth 3)
            "Program data: middle_gateway_data".to_string(), // 7 - Data from middle gateway
            format!("Program {} success", gateway_id),   // 8 - Middle gateway success (depth 2)
            format!("Program {} success", program_a),    // 9 - Program A success (depth 1)
            "Program data: Data outside all calls".to_string(), // 10 - Outside all frames
        ];

        // Test deepest gateway data (index 4) - should succeed
        let result_deepest = event_comes_from_gateway(&complex_logs, 4);
        assert!(
            result_deepest.is_ok(),
            "Should accept data from deepest gateway call"
        );
        assert_eq!(
            result_deepest.unwrap(),
            "Program data: deepest_gateway_data"
        );

        // Test middle gateway data (index 7) - should succeed
        let result_middle = event_comes_from_gateway(&complex_logs, 7);
        assert!(
            result_middle.is_ok(),
            "Should accept data from middle gateway call"
        );
        assert_eq!(result_middle.unwrap(), "Program data: middle_gateway_data");

        // Test data outside all calls (index 10) - should fail
        let result_outside = event_comes_from_gateway(&complex_logs, 10);
        assert!(
            result_outside.is_err(),
            "Should reject data outside all gateway calls"
        );
    }

    #[test]
    fn test_event_comes_from_gateway_complex_nested_scenario_with_logs() {
        let gateway_id = axelar_solana_gateway::id().to_string();
        let program_a = "ProgramA";
        let program_b = "ProgramB";

        // Multiple programs making nested calls
        let complex_logs = vec![
            format!("Program {} invoke [1]", program_a), // 0 - Program A starts
            format!("Program log: success [1]"),         // 1 - Program A log
            format!("Program {} invoke [2]", gateway_id), // 2 - Gateway called by A (depth 2)
            format!("Program log: success [1]"),         // 3 - Gateway log
            format!("Program {} invoke [3]", program_b), // 4 - Program B called by gateway (depth 3)
            format!("Program log: success [1]"),         // 5 - Program B log
            format!("Program {} invoke [4]", gateway_id), // 6 - Gateway called by B (depth 4)
            format!("Program log: success [1]"),         // 7 - Gateway log
            "Program data: deepest_gateway_data".to_string(), // 8 - Data from deepest gateway
            format!("Program log: success [1]"),         // 9 - Gateway log
            format!("Program {} success", gateway_id),   // 10 - Deepest gateway success (depth 4)
            format!("Program log: success [1]"),         // 11 - Program B log
            format!("Program {} success", program_b),    // 12 - Program B success (depth 3)
            format!("Program log: success [1]"),         // 13 - Gateway log
            "Program data: middle_gateway_data".to_string(), // 14 - Data from middle gateway
            format!("Program log: success [1]"),         // 15 - Gateway log
            format!("Program {} success", gateway_id),   // 16 - Middle gateway success (depth 2)
            format!("Program log: success [1]"),         // 17 - Program A log
            format!("Program {} success", program_a),    // 18 - Program A success (depth 1)
            format!("Program log: success [1]"),         // 19 - Spurious log
            "Program data: Data outside all calls".to_string(), // 20 - Outside all frames
            format!("Program log: success [1]"),         // 21 - Spurious log
        ];

        // Test deepest gateway data (index 8) - should succeed
        let result_deepest = event_comes_from_gateway(&complex_logs, 8);
        assert!(
            result_deepest.is_ok(),
            "Should accept data from deepest gateway call"
        );
        assert_eq!(
            result_deepest.unwrap(),
            "Program data: deepest_gateway_data"
        );

        // Test middle gateway data (index 14) - should succeed
        let result_middle = event_comes_from_gateway(&complex_logs, 14);
        assert!(
            result_middle.is_ok(),
            "Should accept data from middle gateway call"
        );
        assert_eq!(result_middle.unwrap(), "Program data: middle_gateway_data");

        // Test data outside all calls (index 10) - should fail
        let result_outside = event_comes_from_gateway(&complex_logs, 20);
        assert!(
            result_outside.is_err(),
            "Should reject data outside all gateway calls"
        );
    }
}
