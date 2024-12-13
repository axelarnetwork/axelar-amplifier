use clarity::vm::types::{
    BufferLength, PrincipalData, SequenceSubtype, TupleTypeSignature, TypeSignature,
};
use clarity::vm::{ClarityName, Value};

use crate::stacks::error::Error;
use crate::stacks::http_client::{Client, TransactionEvents};

pub fn get_verify_contract_params(
    event: &TransactionEvents,
) -> Option<(PrincipalData, PrincipalData)> {
    let payload = get_payload_from_contract_call_event(event).ok()?;

    let inner_verify_contract_type_signature = TupleTypeSignature::try_from(vec![
        (
            ClarityName::from("reference-address"),
            TypeSignature::PrincipalType,
        ),
        (
            ClarityName::from("contract-address"),
            TypeSignature::PrincipalType,
        ),
    ])
    .ok()?;

    let verify_contract_type_signature = TupleTypeSignature::try_from(vec![(
        ClarityName::from("verify-contract"),
        TypeSignature::TupleType(inner_verify_contract_type_signature),
    )])
    .ok()?;

    let mut verify_contract = Value::try_deserialize_bytes(
        &payload,
        &TypeSignature::TupleType(verify_contract_type_signature),
        true,
    )
    .ok()?
    .expect_tuple()
    .ok()?
    .get_owned("verify-contract")
    .ok()?
    .expect_tuple()
    .ok()?;

    let reference_address = verify_contract
        .data_map
        .remove("reference-address")
        .ok_or(Error::PropertyEmpty)
        .ok()?
        .expect_principal()
        .ok()?;
    let contract_address = verify_contract
        .get_owned("contract-address")
        .ok()?
        .expect_principal()
        .ok()?;

    Some((reference_address, contract_address))
}

pub async fn verify_contract_code(
    http_client: &Client,
    reference_address: PrincipalData,
    contract_address: PrincipalData,
) -> Result<bool, Box<dyn std::error::Error>> {
    let reference_contract_code = http_client
        .get_contract_info(format!("{}", reference_address.to_string()).as_str())
        .await?;

    let actual_contract_code = http_client
        .get_contract_info(format!("{}", contract_address.to_string()).as_str())
        .await?;

    Ok(reference_contract_code.source_code == actual_contract_code.source_code)
}

fn get_payload_from_contract_call_event(
    event: &TransactionEvents,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let contract_log = event.contract_log.as_ref().ok_or(Error::PropertyEmpty)?;

    let contract_call_signature = TupleTypeSignature::try_from(vec![(
        ClarityName::from("payload"),
        TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
            64_000u32,
        )?)),
    )])?;

    let hex = contract_log
        .value
        .hex
        .strip_prefix("0x")
        .ok_or(Error::PropertyEmpty)?;

    let contract_call_value = Value::try_deserialize_hex(
        hex,
        &TypeSignature::TupleType(contract_call_signature),
        true,
    )?;

    let payload = contract_call_value
        .expect_tuple()?
        .get_owned("payload")?
        .expect_buff(64_000)?;

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelar_wasm_std::voting::Vote;
    use router_api::ChainName;
    use tokio::test as async_test;

    use crate::handlers::stacks_verify_msg::Message;
    use crate::stacks::http_client::{
        Client, ContractInfo, ContractLog, ContractLogValue, Transaction, TransactionEvents,
    };
    use crate::stacks::verifier::verify_message;
    use crate::types::Hash;

    #[async_test]
    async fn should_not_verify_msg_verify_contract_invalid_contract_code() {
        let mut client = Client::faux();
        faux::when!(client.get_contract_info).then(|contract| {
            if contract == "SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS.sbtc-token" {
                return Ok(ContractInfo {
                    source_code: "mock source code".to_string(),
                });
            }

            Ok(ContractInfo {
                source_code: "invalid source code".to_string(),
            })
        });

        let (source_chain, gateway_address, tx, msg) = get_matching_verify_contract_msg_and_tx();

        assert_eq!(
            verify_message(&source_chain, &gateway_address, &tx, &msg, &client,).await,
            Vote::FailedOnChain
        );
    }

    #[async_test]
    async fn should_verify_msg_verify_contract() {
        let mut client = Client::faux();
        faux::when!(client.get_contract_info).then(|_| {
            Ok(ContractInfo {
                source_code: "mock source code".to_string(),
            })
        });

        let (source_chain, gateway_address, tx, msg) = get_matching_verify_contract_msg_and_tx();

        assert_eq!(
            verify_message(&source_chain, &gateway_address, &tx, &msg, &client).await,
            Vote::SucceededOnChain
        );
    }

    #[async_test]
    async fn should_verify_msg_not_verify_contract_if_payload_does_not_contain_tuple() {
        let client = Client::faux();

        let (source_chain, gateway_address, mut tx, mut msg) =
            get_matching_verify_contract_msg_and_tx();

        // Message is still from Stacks -> Stacks and from contract -> contract,
        // but the payload doesn't contain the verify-contract tuple
        tx.events[1].contract_log = Some(ContractLog {
            contract_id: gateway_address.to_string(),
            topic: "print".to_string(),
            value: ContractLogValue {
                hex: "0x0c000000061164657374696e6174696f6e2d636861696e0d00000006737461636b731c64657374696e6174696f6e2d636f6e74726163742d616464726573730d00000042535431505148514b5630524a585a465931444758384d4e534e5956453356475a4a53525450475a474d2e696e746572636861696e2d746f6b656e2d73657276696365077061796c6f616402000001c40c000000080a6d6573736167652d69640d0000002c617070726f7665642d696e746572636861696e2d746f6b656e2d6465706c6f796d656e742d6d657373616765077061796c6f616402000000a60c0000000608646563696d616c7301000000000000000000000000000000120c6d696e7465722d6279746573020000000100046e616d650d000000176e61746976652d696e746572636861696e2d746f6b656e0673796d626f6c0d0000000349545408746f6b656e2d696402000000206c96e90b60cd71d0b948ae26be1046377a10f46441d595a6d5dd4f4a6a850372047479706501000000000000000000000000000000010e736f757263652d616464726573730d00000004307830300c736f757263652d636861696e0d00000008657468657265756d0d746f6b656e2d61646472657373061a6d78de7b0625dfbfc16c3a8a5735f6dc3dc3f2ce0e73616d706c652d7369702d30313008746f6b656e2d696402000000206c96e90b60cd71d0b948ae26be1046377a10f46441d595a6d5dd4f4a6a8503720a746f6b656e2d74797065010000000000000000000000000000000004747970650d000000177665726966792d696e746572636861696e2d746f6b656e0c7061796c6f61642d686173680200000020e0a3c74b09fa9fc9ce46ab8b6984ffb079f49fc08862a949a14a6eb6ad063c750673656e646572061a6d78de7b0625dfbfc16c3a8a5735f6dc3dc3f2ce18696e746572636861696e2d746f6b656e2d7365727669636504747970650d0000000d636f6e74726163742d63616c6c".to_string(),
            }
        });
        msg.payload_hash = "0xe0a3c74b09fa9fc9ce46ab8b6984ffb079f49fc08862a949a14a6eb6ad063c75"
            .parse()
            .unwrap();

        // Verification will succeed even if the payload doesn't contain the verify-contract tuple
        assert_eq!(
            verify_message(&source_chain, &gateway_address, &tx, &msg, &client).await,
            Vote::SucceededOnChain
        );
    }

    fn get_matching_verify_contract_msg_and_tx() -> (ChainName, String, Transaction, Message) {
        let source_chain = "stacks";
        let gateway_address = "SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.axelar-gateway";
        let its_address = "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.interchain-token-service";

        let message_id = HexTxHashAndEventIndex::new(Hash::random(), 1u64);

        let msg = Message {
            message_id: message_id.clone(),
            source_address: its_address.to_string(),
            destination_chain: source_chain.parse().unwrap(),
            destination_address: its_address.to_string(),
            payload_hash: "0xad65d896da725d0394ae6ce14eed0dd4c4a0f5507d525035936f727e50d57b15"
                .parse()
                .unwrap(),
        };

        let wrong_event = TransactionEvents {
            event_index: 0,
            tx_id: message_id.tx_hash_as_hex().to_string(),
            contract_log: None,
        };

        /*
            payload is:
            {
                verify-contract: {
                    reference-address: SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS.sbtc-token,
                    contract-address: ST32AEEF6WW5Y0NMJ1S8SBSZDAY8R5J32N9D9WJ83.sbtc-token-manager,
                }
            }
        */
        let event = TransactionEvents {
            event_index: 1,
            tx_id: message_id.tx_hash_as_hex().to_string(),
            contract_log: Some(ContractLog {
                contract_id: gateway_address.to_string(),
                topic: "print".to_string(),
                value: ContractLogValue {
                    hex: "0x0c000000061164657374696e6174696f6e2d636861696e0d00000006737461636b731c64657374696e6174696f6e2d636f6e74726163742d616464726573730d00000042535431505148514b5630524a585a465931444758384d4e534e5956453356475a4a53525450475a474d2e696e746572636861696e2d746f6b656e2d73657276696365077061796c6f616402000000870c000000010f7665726966792d636f6e74726163740c0000000210636f6e74726163742d61646472657373061ac4a739e6e70be056920e5195e7ed579182c862aa12736274632d746f6b656e2d6d616e61676572117265666572656e63652d616464726573730615f08277fe51877c890918bb778e0192309b307c390a736274632d746f6b656e0c7061796c6f61642d686173680200000020ad65d896da725d0394ae6ce14eed0dd4c4a0f5507d525035936f727e50d57b150673656e646572061a6d78de7b0625dfbfc16c3a8a5735f6dc3dc3f2ce18696e746572636861696e2d746f6b656e2d7365727669636504747970650d0000000d636f6e74726163742d63616c6c".to_string(),
                }
            }),
        };

        let transaction = Transaction {
            tx_id: message_id.tx_hash.into(),
            nonce: 1,
            sender_address: "whatever".to_string(),
            tx_status: "success".to_string(),
            events: vec![wrong_event, event],
        };

        (
            source_chain.parse().unwrap(),
            gateway_address.to_string(),
            transaction,
            msg,
        )
    }
}
