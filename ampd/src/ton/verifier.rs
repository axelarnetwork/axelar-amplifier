use std::str::FromStr;
use std::sync::Arc;

use axelar_wasm_std::msg_id::HexTxHash;
use ethers_core::types::H256;
use router_api::ChainName;
use ton_utils::{cell_parse_call_contract_log, cell_parse_rotate_signers_log, WeightedSigners};
use tonlib_core::cell::Cell;
use tracing::warn;

use crate::handlers::ton_verify_msg::{FetchingError, Message};
use crate::handlers::ton_verify_verifier_set::VerifierSetConfirmation;
use crate::ton::rpc::TonLog;

const OP_SIGNERS_ROTATED: u32 = 0x0000002A;
const OP_CALL_CONTRACT: u32 = 0x00000009;

// Note: WeightedSigners is empty (has signatures set to 0)
fn parse_rotate_signers_log(
    cell: &Arc<Cell>,
) -> error_stack::Result<WeightedSigners, FetchingError> {
    Ok(cell_parse_rotate_signers_log(cell).map_err(|_| FetchingError::InvalidCall)?)
}

fn parse_call_contract_log(
    message_id: HexTxHash,
    cell: &Arc<Cell>,
) -> error_stack::Result<Message, FetchingError> {
    let (payload_hash, destination_address, destination_chain, source_address) =
        cell_parse_call_contract_log(cell).map_err(|_| FetchingError::InvalidCall)?;

    let destination_chain =
        ChainName::from_str(&destination_chain).map_err(|_| FetchingError::InvalidCall)?;

    Ok(Message {
        message_id,
        payload_hash: H256::from(payload_hash),
        destination_address,
        destination_chain,
        source_address,
    })
}

pub(crate) fn verify_call_contract(log: TonLog, expected_message: &Message) -> bool {
    // check that opcode is correct
    if log.opcode != OP_CALL_CONTRACT {
        return false;
    }

    // decode cell
    if let Ok(result) = parse_call_contract_log(expected_message.message_id.clone(), &log.cell) {
        // compare
        if result != *expected_message {
            return false;
        }
    } else {
        warn!("Failed to parse event body as a contract call data");
        return false;
    }

    true
}

pub(crate) fn verify_verifier_set(
    log: TonLog,
    expected_verifier_set: &VerifierSetConfirmation,
) -> bool {
    // check that opcode is correct
    if log.opcode != OP_SIGNERS_ROTATED {
        return false;
    }

    // decode cell
    if let Ok(derived_weighted_signers) = parse_rotate_signers_log(&log.cell) {
        let expected_weighted_signers =
            WeightedSigners::try_from(expected_verifier_set.verifier_set.clone());
        if expected_weighted_signers.is_err() {
            warn!("Failed to convert verifier set to weighted signers");
            return false;
        }
        let expected_weighted_signers = expected_weighted_signers.unwrap();

        if derived_weighted_signers != expected_weighted_signers {
            return false;
        }
    } else {
        warn!("Failed to parse event body as a contract call data");
        return false;
    }

    true
}

#[cfg(test)]
mod tests {

    use std::collections::BTreeMap;
    use std::sync::Arc;

    use axelar_wasm_std::msg_id::HexTxHash;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use cosmwasm_std::{Addr, HexBinary, Uint128};
    use ethers_core::types::H256;
    use multisig::key::PublicKey;
    use multisig::msg::Signer;
    use multisig::verifier_set::VerifierSet;
    use tonlib_core::cell::Cell;
    use tonlib_core::tlb_types::traits::TLBObject;
    use tonlib_core::TonAddress;

    use super::{
        parse_call_contract_log, parse_rotate_signers_log, verify_call_contract,
        verify_verifier_set, TonLog, WeightedSigners, OP_CALL_CONTRACT, OP_SIGNERS_ROTATED,
    };
    use crate::handlers::ton_verify_verifier_set::VerifierSetConfirmation;
    use crate::ton::rpc::extract_body;

    const TEST_EXAMPLE_TX_LOG_CALL_CONTRACT: &str = "te6cckEBBAEA5QADg4AcPMZ9bgNiMWiFLuLZ3ODT3Qj2rbcRiS/f1NA9opZaWPXUykhs4AH2lBVEFjqex7VaPbPTvuLH5GEs5sIeXm+pcAECAwAcYXZhbGFuY2hlLWZ1amkAVDB4ZDcwNjdBZTNDMzU5ZTgzNzg5MGIyOEI3QkQwZDIwODRDZkRmNDliNQDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE0hlbGxvIGZyb20gUmVsYXllciEAAAAAAAAAAAAAAAAAne0F4Q==";
    const TEST_EXAMPLE_TX_HASH_CALL_CONTRACT: &str = "jq3K6fvoS5e3DwwW4V2N6pxRyB+9BYYBpn0Ps6Qq7Z8=";

    #[test]
    fn should_parse_signers_rotated_log() {
        let signers_rotated_log = "te6cckECCAEAAg8AAWGAAAAAAAAAAAAAAAAAAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAQICzgIFAgEgAwQA4QDoQe/884Qvh1w3RjnS8CZZ+TWMJulDV8d3IZkElUxuAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAOEQ83AI9ItX54QfRoGk0V9NdHRDrfSHHIRkvVvXeQGZdMAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAIBIAYHAOESB7edy2hV4XJ5ZoIYgG4w/nDBxKeP8bX80qk3+1YFOUAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIADhHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZkAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACDebNbp";
        let signers_rotated_log_cell = Arc::new(Cell::from_boc_b64(signers_rotated_log).unwrap());

        let expected_verifier_set = get_expected_signers();
        let expected_weighted_signers =
            WeightedSigners::try_from(expected_verifier_set.clone()).unwrap();

        let derived_weighted_signers = parse_rotate_signers_log(&signers_rotated_log_cell).unwrap();
        assert_eq!(derived_weighted_signers, expected_weighted_signers);
    }

    fn get_expected_signers() -> VerifierSet {
        let mut expected_signers = BTreeMap::new();
        expected_signers.insert(
            "0".to_string(),
            Signer {
                address: Addr::unchecked(""),
                weight: Uint128::from(1u128),
                pub_key: PublicKey::Ed25519(
                    HexBinary::from_hex(
                        "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
                    )
                    .unwrap(),
                ),
            },
        );
        expected_signers.insert(
            "1".to_string(),
            Signer {
                address: Addr::unchecked(""),
                weight: Uint128::from(1u128),
                pub_key: PublicKey::Ed25519(
                    HexBinary::from_hex(
                        "43cdc023d22d5f9e107d1a0693457d35d1d10eb7d21c721192f56f5de40665d3",
                    )
                    .unwrap(),
                ),
            },
        );
        expected_signers.insert(
            "2".to_string(),
            Signer {
                address: Addr::unchecked(""),
                weight: Uint128::from(1u128),
                pub_key: PublicKey::Ed25519(
                    HexBinary::from_hex(
                        "481ede772da15785c9e59a086201b8c3f9c307129e3fc6d7f34aa4dfed5814e5",
                    )
                    .unwrap(),
                ),
            },
        );
        expected_signers.insert(
            "3".to_string(),
            Signer {
                address: Addr::unchecked(""),
                weight: Uint128::from(1u128),
                pub_key: PublicKey::Ed25519(
                    HexBinary::from_hex(
                        "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664",
                    )
                    .unwrap(),
                ),
            },
        );

        VerifierSet {
            signers: expected_signers,
            threshold: Uint128::from(3u128),
            created_at: 1,
        }
    }

    #[test]
    fn should_accept_correct_call_contract() {
        let log = TonLog {
            opcode: OP_CALL_CONTRACT,
            cell: Arc::new(Cell::from_boc_b64(TEST_EXAMPLE_TX_LOG_CALL_CONTRACT).unwrap()),
        };

        let expected_message_cell =
            Arc::new(Cell::from_boc_b64(TEST_EXAMPLE_TX_LOG_CALL_CONTRACT).unwrap());
        print!("Expected message cell is {:?}", expected_message_cell);

        let example_tx_hash = STANDARD.decode(TEST_EXAMPLE_TX_HASH_CALL_CONTRACT).unwrap();
        let example_tx_hash: [u8; 32] = example_tx_hash.try_into().unwrap();
        let message_id = HexTxHash::new(example_tx_hash);

        let expected_message = parse_call_contract_log(message_id, &expected_message_cell).unwrap();
        print!("Expected message is {:?}", expected_message);

        let result = verify_call_contract(log, &expected_message);
        assert!(result);
    }

    #[test]
    fn should_reject_incorrect_call_contract_invalid_opcode() {
        let log = TonLog {
            opcode: OP_SIGNERS_ROTATED, // not a CALL CONTRACT message!
            cell: Arc::new(Cell::from_boc_b64(TEST_EXAMPLE_TX_LOG_CALL_CONTRACT).unwrap()),
        };

        let expected_message_cell =
            Arc::new(Cell::from_boc_b64(TEST_EXAMPLE_TX_LOG_CALL_CONTRACT).unwrap());
        print!("Expected message cell is {:?}", expected_message_cell);

        let example_tx_hash = STANDARD.decode(TEST_EXAMPLE_TX_HASH_CALL_CONTRACT).unwrap();
        let example_tx_hash: [u8; 32] = example_tx_hash.try_into().unwrap();
        let message_id = HexTxHash::new(example_tx_hash);

        let expected_message = parse_call_contract_log(message_id, &expected_message_cell).unwrap();
        print!("Expected message is {:?}", expected_message);

        let result = verify_call_contract(log, &expected_message);
        assert!(!result);
    }

    #[test]
    fn should_reject_incorrect_call_contract_faked_data() {
        let log = TonLog {
            opcode: OP_CALL_CONTRACT,
            cell: Arc::new(Cell::from_boc_b64(TEST_EXAMPLE_TX_LOG_CALL_CONTRACT).unwrap()),
        };

        let expected_message_cell =
            Arc::new(Cell::from_boc_b64(TEST_EXAMPLE_TX_LOG_CALL_CONTRACT).unwrap());
        print!("Expected message cell is {:?}", expected_message_cell);

        let example_tx_hash = STANDARD.decode(TEST_EXAMPLE_TX_HASH_CALL_CONTRACT).unwrap();
        let example_tx_hash: [u8; 32] = example_tx_hash.try_into().unwrap();
        let message_id = HexTxHash::new(example_tx_hash);

        let mut bad_message = parse_call_contract_log(message_id, &expected_message_cell).unwrap();
        bad_message.destination_address = String::from("Bad String"); // this is now a faked message
        print!("Bad message is {:?}", bad_message);

        let result = verify_call_contract(log, &bad_message);
        assert!(!result);
    }

    #[test]
    fn should_reject_incorrect_call_contract_unparsable_data() {
        let cell = Cell::from_boc_b64(TEST_EXAMPLE_TX_LOG_CALL_CONTRACT).unwrap();
        let mut correct_cell = cell.parser();
        let partial_cell = correct_cell.next_reference().unwrap();
        let log = TonLog {
            opcode: OP_CALL_CONTRACT,
            cell: partial_cell,
        };

        let expected_message_cell =
            Arc::new(Cell::from_boc_b64(TEST_EXAMPLE_TX_LOG_CALL_CONTRACT).unwrap());
        print!("Expected message cell is {:?}", expected_message_cell);

        let example_tx_hash = STANDARD.decode(TEST_EXAMPLE_TX_HASH_CALL_CONTRACT).unwrap();
        let example_tx_hash: [u8; 32] = example_tx_hash.try_into().unwrap();
        let message_id = HexTxHash::new(example_tx_hash);

        let expected_message = parse_call_contract_log(message_id, &expected_message_cell).unwrap();
        print!("Expected message is {:?}", expected_message);

        let result = verify_call_contract(log, &expected_message);
        assert!(!result);
    }

    #[test]
    fn should_accept_correct_signer_rotation() {
        let msg_id = HexTxHash::new(H256::repeat_byte(1));

        let expected_verifier_set = get_expected_signers();
        let expected_verifier_set_confirmation = VerifierSetConfirmation {
            message_id: msg_id.to_string().parse().unwrap(),
            verifier_set: expected_verifier_set,
        };

        let rpc_return_text = r#"{"transactions":[{"account":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","hash":"L/DSNQ43lWUDdga8h4ci8hVp+nVS6/BxEF7KrAO0yTo=","lt":"36582626000003","now":1751972976,"mc_block_seqno":33013054,"trace_id":"6h4rXxxaXBcwgFnNiyyzXolMBo6wDeqiW2+LIq8feHE=","prev_trans_hash":"BoNe1HOkg+5k8XGGuY5iRcuz8Nwkc5rxT7NuM/vDP/E=","prev_trans_lt":"36552848000003","orig_status":"active","end_status":"active","total_fees":"6617389","total_fees_extra_currencies":{},"description":{"type":"ord","aborted":false,"destroyed":false,"credit_first":false,"storage_ph":{"storage_fees_collected":"72858","status_change":"unchanged"},"credit_ph":{"credit":"98993600"},"compute_ph":{"skipped":false,"success":true,"msg_state_used":false,"account_activated":false,"gas_fees":"5138000","gas_used":"12845","gas_limit":"247484","mode":0,"exit_code":0,"vm_steps":274,"vm_init_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","vm_final_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"action":{"success":true,"valid":true,"no_funds":false,"status_change":"unchanged","total_fwd_fees":"1708400","total_action_fees":"1406531","result_code":0,"tot_actions":2,"spec_actions":0,"skipped_actions":0,"msgs_created":2,"action_list_hash":"hBjjQRhmPzm+RKgy6U+Ege0Hb0UxD5cNxn2hErwF/To=","tot_msg_size":{"cells":"7","bits":"3110"}}},"block_ref":{"workchain":0,"shard":"8000000000000000","seqno":34903585},"in_msg":{"hash":"59r5FWJBKUv8C7E2szCKDhjdsz0t9hLJM5OiFHToemc=","source":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","destination":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","value":"98993600","value_extra_currencies":{},"fwd_fee":"670939","ihr_fee":"0","created_lt":"36582626000002","created_at":"1751972976","opcode":"0x0000002a","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"o7V4cZZJdfDYiGUOySLXQiP8zq9cSASvIlmbO/ucJzI=","body":"removed","decoded":null},"init_state":null},"out_msgs":[{"hash":"WsQVGIoOXjS+BqJ46ebFGmzBUNGOY3t2DbZ1/EXK9h4=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":null,"value":null,"value_extra_currencies":null,"fwd_fee":null,"ihr_fee":null,"created_lt":"36582626000004","created_at":"1751972976","opcode":"0x8011315a","ihr_disabled":null,"bounce":null,"bounced":null,"import_fee":null,"message_content":{"hash":"laYhaSZO6QjQmRsJsn02MK8hcwwIgxMIYX2oFcjFNdA=","body":"te6cckECCAEAAg8AAWGAAAAAAAAAAAAAAAAAAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAQICzgIFAgEgAwQA4QDoQe/884Qvh1w3RjnS8CZZ+TWMJulDV8d3IZkElUxuAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAOEQ83AI9ItX54QfRoGk0V9NdHRDrfSHHIRkvVvXeQGZdMAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAIBIAYHAOESB7edy2hV4XJ5ZoIYgG4w/nDBxKeP8bX80qk3+1YFOUAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIADhHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZkAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACDebNbp","decoded":null},"init_state":null},{"hash":"5+pjUx9a/8fmExUlLPQKUWSf+p+/HGhbuiL6Trhuufw=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","value":"93402800","value_extra_currencies":{},"fwd_fee":"301869","ihr_fee":"0","created_lt":"36582626000005","created_at":"1751972976","opcode":"0x00000018","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"qvrlOoIcMk+4fXd5wBBiFUGFVRoCDCkhuAdj+PADXBE=","body":"te6cckEBAQEABgAACAAAABhDnyiV","decoded":null},"init_state":null}],"account_state_before":{"hash":"posCwcSHfOabFTEJpZf3DjjrwdCa0yhl9DX9LTojxY4=","balance":"2717267789","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"account_state_after":{"hash":"4OBdR8k83rjRSwwreZI6a8TmlsuKN5MrCbM/6B+8bFw=","balance":"2715939331","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"emulated":false}]}"#;

        let example_gateway =
            TonAddress::from_base64_url("kQAAGUqtjkIr7fQ_7nRtbZKdNp26slRopp1RNwbqaXi2OnXH")
                .unwrap();

        let log = extract_body(&example_gateway, rpc_return_text).unwrap();

        assert!(verify_verifier_set(
            log,
            &expected_verifier_set_confirmation
        ));
    }

    #[test]
    fn should_reject_incorrect_signer_rotation_opcode() {
        let msg_id = HexTxHash::new(H256::repeat_byte(1));

        let expected_verifier_set = get_expected_signers();
        let expected_verifier_set_confirmation = VerifierSetConfirmation {
            message_id: msg_id.to_string().parse().unwrap(),
            verifier_set: expected_verifier_set,
        };

        // notice that "opcode" is "0xff00dc2a"
        let rpc_return_text = r#"{"transactions":[{"account":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","hash":"L/DSNQ43lWUDdga8h4ci8hVp+nVS6/BxEF7KrAO0yTo=","lt":"36582626000003","now":1751972976,"mc_block_seqno":33013054,"trace_id":"6h4rXxxaXBcwgFnNiyyzXolMBo6wDeqiW2+LIq8feHE=","prev_trans_hash":"BoNe1HOkg+5k8XGGuY5iRcuz8Nwkc5rxT7NuM/vDP/E=","prev_trans_lt":"36552848000003","orig_status":"active","end_status":"active","total_fees":"6617389","total_fees_extra_currencies":{},"description":{"type":"ord","aborted":false,"destroyed":false,"credit_first":false,"storage_ph":{"storage_fees_collected":"72858","status_change":"unchanged"},"credit_ph":{"credit":"98993600"},"compute_ph":{"skipped":false,"success":true,"msg_state_used":false,"account_activated":false,"gas_fees":"5138000","gas_used":"12845","gas_limit":"247484","mode":0,"exit_code":0,"vm_steps":274,"vm_init_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","vm_final_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"action":{"success":true,"valid":true,"no_funds":false,"status_change":"unchanged","total_fwd_fees":"1708400","total_action_fees":"1406531","result_code":0,"tot_actions":2,"spec_actions":0,"skipped_actions":0,"msgs_created":2,"action_list_hash":"hBjjQRhmPzm+RKgy6U+Ege0Hb0UxD5cNxn2hErwF/To=","tot_msg_size":{"cells":"7","bits":"3110"}}},"block_ref":{"workchain":0,"shard":"8000000000000000","seqno":34903585},"in_msg":{"hash":"59r5FWJBKUv8C7E2szCKDhjdsz0t9hLJM5OiFHToemc=","source":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","destination":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","value":"98993600","value_extra_currencies":{},"fwd_fee":"670939","ihr_fee":"0","created_lt":"36582626000002","created_at":"1751972976","opcode":"0xff00dc2a","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"o7V4cZZJdfDYiGUOySLXQiP8zq9cSASvIlmbO/ucJzI=","body":"removed","decoded":null},"init_state":null},"out_msgs":[{"hash":"WsQVGIoOXjS+BqJ46ebFGmzBUNGOY3t2DbZ1/EXK9h4=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":null,"value":null,"value_extra_currencies":null,"fwd_fee":null,"ihr_fee":null,"created_lt":"36582626000004","created_at":"1751972976","opcode":"0x8011315a","ihr_disabled":null,"bounce":null,"bounced":null,"import_fee":null,"message_content":{"hash":"laYhaSZO6QjQmRsJsn02MK8hcwwIgxMIYX2oFcjFNdA=","body":"te6cckECCAEAAg8AAWGAAAAAAAAAAAAAAAAAAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAQICzgIFAgEgAwQA4QDoQe/884Qvh1w3RjnS8CZZ+TWMJulDV8d3IZkElUxuAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAOEQ83AI9ItX54QfRoGk0V9NdHRDrfSHHIRkvVvXeQGZdMAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAIBIAYHAOESB7edy2hV4XJ5ZoIYgG4w/nDBxKeP8bX80qk3+1YFOUAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIADhHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZkAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACDebNbp","decoded":null},"init_state":null},{"hash":"5+pjUx9a/8fmExUlLPQKUWSf+p+/HGhbuiL6Trhuufw=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","value":"93402800","value_extra_currencies":{},"fwd_fee":"301869","ihr_fee":"0","created_lt":"36582626000005","created_at":"1751972976","opcode":"0x00000018","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"qvrlOoIcMk+4fXd5wBBiFUGFVRoCDCkhuAdj+PADXBE=","body":"te6cckEBAQEABgAACAAAABhDnyiV","decoded":null},"init_state":null}],"account_state_before":{"hash":"posCwcSHfOabFTEJpZf3DjjrwdCa0yhl9DX9LTojxY4=","balance":"2717267789","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"account_state_after":{"hash":"4OBdR8k83rjRSwwreZI6a8TmlsuKN5MrCbM/6B+8bFw=","balance":"2715939331","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"emulated":false}]}"#;

        let example_gateway =
            TonAddress::from_base64_url("kQAAGUqtjkIr7fQ_7nRtbZKdNp26slRopp1RNwbqaXi2OnXH")
                .unwrap();

        let log = extract_body(&example_gateway, rpc_return_text).unwrap();

        assert!(!verify_verifier_set(
            log,
            &expected_verifier_set_confirmation
        ));
    }

    #[test]
    fn should_reject_incorrect_signer_rotation_unparsable() {
        let msg_id = HexTxHash::new(H256::repeat_byte(1));

        let expected_verifier_set = get_expected_signers();
        let expected_verifier_set_confirmation = VerifierSetConfirmation {
            message_id: msg_id.to_string().parse().unwrap(),
            verifier_set: expected_verifier_set,
        };

        let rpc_return_text = r#"{"transactions":[{"account":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","hash":"L/DSNQ43lWUDdga8h4ci8hVp+nVS6/BxEF7KrAO0yTo=","lt":"36582626000003","now":1751972976,"mc_block_seqno":33013054,"trace_id":"6h4rXxxaXBcwgFnNiyyzXolMBo6wDeqiW2+LIq8feHE=","prev_trans_hash":"BoNe1HOkg+5k8XGGuY5iRcuz8Nwkc5rxT7NuM/vDP/E=","prev_trans_lt":"36552848000003","orig_status":"active","end_status":"active","total_fees":"6617389","total_fees_extra_currencies":{},"description":{"type":"ord","aborted":false,"destroyed":false,"credit_first":false,"storage_ph":{"storage_fees_collected":"72858","status_change":"unchanged"},"credit_ph":{"credit":"98993600"},"compute_ph":{"skipped":false,"success":true,"msg_state_used":false,"account_activated":false,"gas_fees":"5138000","gas_used":"12845","gas_limit":"247484","mode":0,"exit_code":0,"vm_steps":274,"vm_init_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","vm_final_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"action":{"success":true,"valid":true,"no_funds":false,"status_change":"unchanged","total_fwd_fees":"1708400","total_action_fees":"1406531","result_code":0,"tot_actions":2,"spec_actions":0,"skipped_actions":0,"msgs_created":2,"action_list_hash":"hBjjQRhmPzm+RKgy6U+Ege0Hb0UxD5cNxn2hErwF/To=","tot_msg_size":{"cells":"7","bits":"3110"}}},"block_ref":{"workchain":0,"shard":"8000000000000000","seqno":34903585},"in_msg":{"hash":"59r5FWJBKUv8C7E2szCKDhjdsz0t9hLJM5OiFHToemc=","source":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","destination":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","value":"98993600","value_extra_currencies":{},"fwd_fee":"670939","ihr_fee":"0","created_lt":"36582626000002","created_at":"1751972976","opcode":"0x0000002a","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"o7V4cZZJdfDYiGUOySLXQiP8zq9cSASvIlmbO/ucJzI=","body":"removed","decoded":null},"init_state":null},"out_msgs":[{"hash":"WsQVGIoOXjS+BqJ46ebFGmzBUNGOY3t2DbZ1/EXK9h4=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":null,"value":null,"value_extra_currencies":null,"fwd_fee":null,"ihr_fee":null,"created_lt":"36582626000004","created_at":"1751972976","opcode":"0x8011315a","ihr_disabled":null,"bounce":null,"bounced":null,"import_fee":null,"message_content":{"hash":"laYhaSZO6QjQmRsJsn02MK8hcwwIgxMIYX2oFcjFNdA=","body":"te6cckECCAEAAg8AAWGAAAAAAAAAAAAAAAAAAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAQICzgIFAgEgAwQA4QDoQe/884Qvh1w3RjnS8CZZ+TWMJulDV8d3IZkElUxuAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAOEQ83AI9ItX54QfRoGk0V9NdHRDrfSHHIRkvVvXeQGZdMAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAIBIAYHAOESB7edy2hV4XJ5ZoIYgG4w/nDBxKeP8bX80qk3+1YFOUAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIADhHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZkAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACDebNbp","decoded":null},"init_state":null},{"hash":"5+pjUx9a/8fmExUlLPQKUWSf+p+/HGhbuiL6Trhuufw=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","value":"93402800","value_extra_currencies":{},"fwd_fee":"301869","ihr_fee":"0","created_lt":"36582626000005","created_at":"1751972976","opcode":"0x00000018","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"qvrlOoIcMk+4fXd5wBBiFUGFVRoCDCkhuAdj+PADXBE=","body":"te6cckEBAQEABgAACAAAABhDnyiV","decoded":null},"init_state":null}],"account_state_before":{"hash":"posCwcSHfOabFTEJpZf3DjjrwdCa0yhl9DX9LTojxY4=","balance":"2717267789","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"account_state_after":{"hash":"4OBdR8k83rjRSwwreZI6a8TmlsuKN5MrCbM/6B+8bFw=","balance":"2715939331","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"emulated":false}]}"#;

        let example_gateway =
            TonAddress::from_base64_url("kQAAGUqtjkIr7fQ_7nRtbZKdNp26slRopp1RNwbqaXi2OnXH")
                .unwrap();

        let mut log = extract_body(&example_gateway, rpc_return_text).unwrap();

        let mut correct_cell = log.cell.parser();
        let partial_cell = correct_cell.next_reference().unwrap();
        log.cell = partial_cell;

        assert!(!verify_verifier_set(
            log,
            &expected_verifier_set_confirmation
        ));
    }

    #[test]
    fn should_reject_incorrect_signer_rotation_different() {
        let msg_id = HexTxHash::new(H256::repeat_byte(1));

        let mut incorrect_verifier_set = get_expected_signers();
        incorrect_verifier_set.created_at += 1;

        let incorrect_verifier_set_confirmation = VerifierSetConfirmation {
            message_id: msg_id.to_string().parse().unwrap(),
            verifier_set: incorrect_verifier_set,
        };

        let rpc_return_text = r#"{"transactions":[{"account":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","hash":"L/DSNQ43lWUDdga8h4ci8hVp+nVS6/BxEF7KrAO0yTo=","lt":"36582626000003","now":1751972976,"mc_block_seqno":33013054,"trace_id":"6h4rXxxaXBcwgFnNiyyzXolMBo6wDeqiW2+LIq8feHE=","prev_trans_hash":"BoNe1HOkg+5k8XGGuY5iRcuz8Nwkc5rxT7NuM/vDP/E=","prev_trans_lt":"36552848000003","orig_status":"active","end_status":"active","total_fees":"6617389","total_fees_extra_currencies":{},"description":{"type":"ord","aborted":false,"destroyed":false,"credit_first":false,"storage_ph":{"storage_fees_collected":"72858","status_change":"unchanged"},"credit_ph":{"credit":"98993600"},"compute_ph":{"skipped":false,"success":true,"msg_state_used":false,"account_activated":false,"gas_fees":"5138000","gas_used":"12845","gas_limit":"247484","mode":0,"exit_code":0,"vm_steps":274,"vm_init_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","vm_final_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"action":{"success":true,"valid":true,"no_funds":false,"status_change":"unchanged","total_fwd_fees":"1708400","total_action_fees":"1406531","result_code":0,"tot_actions":2,"spec_actions":0,"skipped_actions":0,"msgs_created":2,"action_list_hash":"hBjjQRhmPzm+RKgy6U+Ege0Hb0UxD5cNxn2hErwF/To=","tot_msg_size":{"cells":"7","bits":"3110"}}},"block_ref":{"workchain":0,"shard":"8000000000000000","seqno":34903585},"in_msg":{"hash":"59r5FWJBKUv8C7E2szCKDhjdsz0t9hLJM5OiFHToemc=","source":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","destination":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","value":"98993600","value_extra_currencies":{},"fwd_fee":"670939","ihr_fee":"0","created_lt":"36582626000002","created_at":"1751972976","opcode":"0x0000002a","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"o7V4cZZJdfDYiGUOySLXQiP8zq9cSASvIlmbO/ucJzI=","body":"removed","decoded":null},"init_state":null},"out_msgs":[{"hash":"WsQVGIoOXjS+BqJ46ebFGmzBUNGOY3t2DbZ1/EXK9h4=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":null,"value":null,"value_extra_currencies":null,"fwd_fee":null,"ihr_fee":null,"created_lt":"36582626000004","created_at":"1751972976","opcode":"0x8011315a","ihr_disabled":null,"bounce":null,"bounced":null,"import_fee":null,"message_content":{"hash":"laYhaSZO6QjQmRsJsn02MK8hcwwIgxMIYX2oFcjFNdA=","body":"te6cckECCAEAAg8AAWGAAAAAAAAAAAAAAAAAAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAQICzgIFAgEgAwQA4QDoQe/884Qvh1w3RjnS8CZZ+TWMJulDV8d3IZkElUxuAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAOEQ83AI9ItX54QfRoGk0V9NdHRDrfSHHIRkvVvXeQGZdMAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAIBIAYHAOESB7edy2hV4XJ5ZoIYgG4w/nDBxKeP8bX80qk3+1YFOUAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIADhHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZkAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACDebNbp","decoded":null},"init_state":null},{"hash":"5+pjUx9a/8fmExUlLPQKUWSf+p+/HGhbuiL6Trhuufw=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","value":"93402800","value_extra_currencies":{},"fwd_fee":"301869","ihr_fee":"0","created_lt":"36582626000005","created_at":"1751972976","opcode":"0x00000018","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"qvrlOoIcMk+4fXd5wBBiFUGFVRoCDCkhuAdj+PADXBE=","body":"te6cckEBAQEABgAACAAAABhDnyiV","decoded":null},"init_state":null}],"account_state_before":{"hash":"posCwcSHfOabFTEJpZf3DjjrwdCa0yhl9DX9LTojxY4=","balance":"2717267789","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"account_state_after":{"hash":"4OBdR8k83rjRSwwreZI6a8TmlsuKN5MrCbM/6B+8bFw=","balance":"2715939331","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"emulated":false}]}"#;

        let example_gateway =
            TonAddress::from_base64_url("kQAAGUqtjkIr7fQ_7nRtbZKdNp26slRopp1RNwbqaXi2OnXH")
                .unwrap();

        let log = extract_body(&example_gateway, rpc_return_text).unwrap();

        assert!(!verify_verifier_set(
            log,
            &incorrect_verifier_set_confirmation
        ));
    }

    #[test]
    fn should_reject_incorrect_signer_rotation_conversion_failure_key_type() {
        let msg_id = HexTxHash::new(H256::repeat_byte(1));

        let mut incorrect_verifier_set = get_expected_signers();
        incorrect_verifier_set.signers.insert(
            "4".to_string(),
            Signer {
                address: Addr::unchecked(""),
                weight: Uint128::from(1u128),
                pub_key: PublicKey::Ecdsa(
                    // incorrect key type used
                    HexBinary::from_hex(
                        "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664",
                    )
                    .unwrap(),
                ),
            },
        );

        let incorrect_verifier_set_confirmation = VerifierSetConfirmation {
            message_id: msg_id.to_string().parse().unwrap(),
            verifier_set: incorrect_verifier_set,
        };

        let rpc_return_text = r#"{"transactions":[{"account":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","hash":"L/DSNQ43lWUDdga8h4ci8hVp+nVS6/BxEF7KrAO0yTo=","lt":"36582626000003","now":1751972976,"mc_block_seqno":33013054,"trace_id":"6h4rXxxaXBcwgFnNiyyzXolMBo6wDeqiW2+LIq8feHE=","prev_trans_hash":"BoNe1HOkg+5k8XGGuY5iRcuz8Nwkc5rxT7NuM/vDP/E=","prev_trans_lt":"36552848000003","orig_status":"active","end_status":"active","total_fees":"6617389","total_fees_extra_currencies":{},"description":{"type":"ord","aborted":false,"destroyed":false,"credit_first":false,"storage_ph":{"storage_fees_collected":"72858","status_change":"unchanged"},"credit_ph":{"credit":"98993600"},"compute_ph":{"skipped":false,"success":true,"msg_state_used":false,"account_activated":false,"gas_fees":"5138000","gas_used":"12845","gas_limit":"247484","mode":0,"exit_code":0,"vm_steps":274,"vm_init_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","vm_final_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"action":{"success":true,"valid":true,"no_funds":false,"status_change":"unchanged","total_fwd_fees":"1708400","total_action_fees":"1406531","result_code":0,"tot_actions":2,"spec_actions":0,"skipped_actions":0,"msgs_created":2,"action_list_hash":"hBjjQRhmPzm+RKgy6U+Ege0Hb0UxD5cNxn2hErwF/To=","tot_msg_size":{"cells":"7","bits":"3110"}}},"block_ref":{"workchain":0,"shard":"8000000000000000","seqno":34903585},"in_msg":{"hash":"59r5FWJBKUv8C7E2szCKDhjdsz0t9hLJM5OiFHToemc=","source":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","destination":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","value":"98993600","value_extra_currencies":{},"fwd_fee":"670939","ihr_fee":"0","created_lt":"36582626000002","created_at":"1751972976","opcode":"0x0000002a","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"o7V4cZZJdfDYiGUOySLXQiP8zq9cSASvIlmbO/ucJzI=","body":"removed","decoded":null},"init_state":null},"out_msgs":[{"hash":"WsQVGIoOXjS+BqJ46ebFGmzBUNGOY3t2DbZ1/EXK9h4=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":null,"value":null,"value_extra_currencies":null,"fwd_fee":null,"ihr_fee":null,"created_lt":"36582626000004","created_at":"1751972976","opcode":"0x8011315a","ihr_disabled":null,"bounce":null,"bounced":null,"import_fee":null,"message_content":{"hash":"laYhaSZO6QjQmRsJsn02MK8hcwwIgxMIYX2oFcjFNdA=","body":"te6cckECCAEAAg8AAWGAAAAAAAAAAAAAAAAAAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAQICzgIFAgEgAwQA4QDoQe/884Qvh1w3RjnS8CZZ+TWMJulDV8d3IZkElUxuAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAOEQ83AI9ItX54QfRoGk0V9NdHRDrfSHHIRkvVvXeQGZdMAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAIBIAYHAOESB7edy2hV4XJ5ZoIYgG4w/nDBxKeP8bX80qk3+1YFOUAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIADhHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZkAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACDebNbp","decoded":null},"init_state":null},{"hash":"5+pjUx9a/8fmExUlLPQKUWSf+p+/HGhbuiL6Trhuufw=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","value":"93402800","value_extra_currencies":{},"fwd_fee":"301869","ihr_fee":"0","created_lt":"36582626000005","created_at":"1751972976","opcode":"0x00000018","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"qvrlOoIcMk+4fXd5wBBiFUGFVRoCDCkhuAdj+PADXBE=","body":"te6cckEBAQEABgAACAAAABhDnyiV","decoded":null},"init_state":null}],"account_state_before":{"hash":"posCwcSHfOabFTEJpZf3DjjrwdCa0yhl9DX9LTojxY4=","balance":"2717267789","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"account_state_after":{"hash":"4OBdR8k83rjRSwwreZI6a8TmlsuKN5MrCbM/6B+8bFw=","balance":"2715939331","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"emulated":false}]}"#;

        let example_gateway =
            TonAddress::from_base64_url("kQAAGUqtjkIr7fQ_7nRtbZKdNp26slRopp1RNwbqaXi2OnXH")
                .unwrap();

        let log = extract_body(&example_gateway, rpc_return_text).unwrap();

        assert!(!verify_verifier_set(
            log,
            &incorrect_verifier_set_confirmation
        ));
    }

    #[test]
    fn should_reject_incorrect_signer_rotation_conversion_failure_dict_key_error() {
        let msg_id = HexTxHash::new(H256::repeat_byte(1));

        let mut incorrect_verifier_set = get_expected_signers();
        incorrect_verifier_set.signers.insert(
            "invalid_key".to_string(),
            Signer {
                address: Addr::unchecked(""),
                weight: Uint128::from(1u128),
                pub_key: PublicKey::Ed25519(
                    HexBinary::from_hex(
                        "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664",
                    )
                    .unwrap(),
                ),
            },
        );

        let incorrect_verifier_set_confirmation = VerifierSetConfirmation {
            message_id: msg_id.to_string().parse().unwrap(),
            verifier_set: incorrect_verifier_set,
        };

        let rpc_return_text = r#"{"transactions":[{"account":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","hash":"L/DSNQ43lWUDdga8h4ci8hVp+nVS6/BxEF7KrAO0yTo=","lt":"36582626000003","now":1751972976,"mc_block_seqno":33013054,"trace_id":"6h4rXxxaXBcwgFnNiyyzXolMBo6wDeqiW2+LIq8feHE=","prev_trans_hash":"BoNe1HOkg+5k8XGGuY5iRcuz8Nwkc5rxT7NuM/vDP/E=","prev_trans_lt":"36552848000003","orig_status":"active","end_status":"active","total_fees":"6617389","total_fees_extra_currencies":{},"description":{"type":"ord","aborted":false,"destroyed":false,"credit_first":false,"storage_ph":{"storage_fees_collected":"72858","status_change":"unchanged"},"credit_ph":{"credit":"98993600"},"compute_ph":{"skipped":false,"success":true,"msg_state_used":false,"account_activated":false,"gas_fees":"5138000","gas_used":"12845","gas_limit":"247484","mode":0,"exit_code":0,"vm_steps":274,"vm_init_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","vm_final_state_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"action":{"success":true,"valid":true,"no_funds":false,"status_change":"unchanged","total_fwd_fees":"1708400","total_action_fees":"1406531","result_code":0,"tot_actions":2,"spec_actions":0,"skipped_actions":0,"msgs_created":2,"action_list_hash":"hBjjQRhmPzm+RKgy6U+Ege0Hb0UxD5cNxn2hErwF/To=","tot_msg_size":{"cells":"7","bits":"3110"}}},"block_ref":{"workchain":0,"shard":"8000000000000000","seqno":34903585},"in_msg":{"hash":"59r5FWJBKUv8C7E2szCKDhjdsz0t9hLJM5OiFHToemc=","source":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","destination":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","value":"98993600","value_extra_currencies":{},"fwd_fee":"670939","ihr_fee":"0","created_lt":"36582626000002","created_at":"1751972976","opcode":"0x0000002a","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"o7V4cZZJdfDYiGUOySLXQiP8zq9cSASvIlmbO/ucJzI=","body":"removed","decoded":null},"init_state":null},"out_msgs":[{"hash":"WsQVGIoOXjS+BqJ46ebFGmzBUNGOY3t2DbZ1/EXK9h4=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":null,"value":null,"value_extra_currencies":null,"fwd_fee":null,"ihr_fee":null,"created_lt":"36582626000004","created_at":"1751972976","opcode":"0x8011315a","ihr_disabled":null,"bounce":null,"bounced":null,"import_fee":null,"message_content":{"hash":"laYhaSZO6QjQmRsJsn02MK8hcwwIgxMIYX2oFcjFNdA=","body":"te6cckECCAEAAg8AAWGAAAAAAAAAAAAAAAAAAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAQICzgIFAgEgAwQA4QDoQe/884Qvh1w3RjnS8CZZ+TWMJulDV8d3IZkElUxuAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAOEQ83AI9ItX54QfRoGk0V9NdHRDrfSHHIRkvVvXeQGZdMAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAIBIAYHAOESB7edy2hV4XJ5ZoIYgG4w/nDBxKeP8bX80qk3+1YFOUAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIADhHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZkAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACDebNbp","decoded":null},"init_state":null},{"hash":"5+pjUx9a/8fmExUlLPQKUWSf+p+/HGhbuiL6Trhuufw=","source":"0:00194AAD8E422BEDF43FEE746D6D929D369DBAB25468A69D513706EA6978B63A","destination":"0:898AD13C059F2A3A69576A010C41AF239B487BC555EABEB9A5894DEB11299330","value":"93402800","value_extra_currencies":{},"fwd_fee":"301869","ihr_fee":"0","created_lt":"36582626000005","created_at":"1751972976","opcode":"0x00000018","ihr_disabled":true,"bounce":true,"bounced":false,"import_fee":null,"message_content":{"hash":"qvrlOoIcMk+4fXd5wBBiFUGFVRoCDCkhuAdj+PADXBE=","body":"te6cckEBAQEABgAACAAAABhDnyiV","decoded":null},"init_state":null}],"account_state_before":{"hash":"posCwcSHfOabFTEJpZf3DjjrwdCa0yhl9DX9LTojxY4=","balance":"2717267789","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"account_state_after":{"hash":"4OBdR8k83rjRSwwreZI6a8TmlsuKN5MrCbM/6B+8bFw=","balance":"2715939331","extra_currencies":{},"account_status":"active","frozen_hash":null,"data_hash":"86U+qAM9Gn2Vq9aPLlAW+s6FEpXYZG6v9LwsXNapESw=","code_hash":"vqMbw5w/UEelgUr4xN5vkmkbOqjfAcck49G02pV9Pho="},"emulated":false}]}"#;

        let example_gateway =
            TonAddress::from_base64_url("kQAAGUqtjkIr7fQ_7nRtbZKdNp26slRopp1RNwbqaXi2OnXH")
                .unwrap();

        let log = extract_body(&example_gateway, rpc_return_text).unwrap();

        assert!(!verify_verifier_set(
            log,
            &incorrect_verifier_set_confirmation
        ));
    }
}
