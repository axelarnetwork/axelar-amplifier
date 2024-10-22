use crate::handlers::stacks_verify_msg::Message;
use crate::stacks::error::Error;
use crate::stacks::http_client::{Client, TransactionEvents};
use crate::stacks::verifier::{CONTRACT_CALL_TYPE, PRINT_TOPIC};
use crate::types::Hash;
use clarity::codec::StacksMessageCodec;
use clarity::vm::types::{
    BufferLength, PrincipalData, SequenceSubtype, StringSubtype, TupleData, TupleTypeSignature,
    TypeSignature,
};
use clarity::vm::{ClarityName, Value};
use ethers_core::abi::{encode, Token};
use sha3::{Digest, Keccak256};

const MESSAGE_TYPE_INTERCHAIN_TRANSFER: u128 = 0;
const MESSAGE_TYPE_DEPLOY_INTERCHAIN_TOKEN: u128 = 1;
const MESSAGE_TYPE_DEPLOY_TOKEN_MANAGER: u128 = 2;
const MESSAGE_TYPE_SEND_TO_HUB: u128 = 3;

const VERIFY_INTERCHAIN_TOKEN: &str = "verify-interchain-token";
const VERIFY_TOKEN_MANAGER: &str = "verify-token-manager";

pub fn get_its_hub_payload_hash(
    event: &TransactionEvents,
) -> Result<Hash, Box<dyn std::error::Error>> {
    let tuple_data = get_its_hub_call_params(event)?;

    // All messages should go through ITS hub
    if !tuple_data
        .get("type")?
        .eq(&Value::UInt(MESSAGE_TYPE_SEND_TO_HUB))
    {
        return Err(Error::InvalidCall.into());
    }

    let destination_chain = tuple_data
        .get("destination-chain")?
        .clone()
        .expect_ascii()?;
    let payload = tuple_data.get_owned("payload")?.expect_buff(10240)?;

    let subtuple_type_signature =
        TupleTypeSignature::try_from(vec![(ClarityName::from("type"), TypeSignature::UIntType)])?;

    let original_its_call = Value::try_deserialize_bytes(
        &payload,
        &TypeSignature::TupleType(subtuple_type_signature),
        true,
    )?
    .expect_tuple()?;

    let its_type = original_its_call.get_owned("type")?.expect_u128()?;

    let abi_payload = match its_type {
        MESSAGE_TYPE_INTERCHAIN_TRANSFER => get_its_interchain_transfer_abi_payload(payload),
        MESSAGE_TYPE_DEPLOY_INTERCHAIN_TOKEN => {
            get_its_deploy_interchain_token_abi_payload(payload)
        }
        MESSAGE_TYPE_DEPLOY_TOKEN_MANAGER => get_its_deploy_token_manager_payload(payload),
        _ => {
            return Err(Error::InvalidCall.into());
        }
    }?;

    // Convert to ITS payload and use its hash to verify the message
    let abi_payload = encode(&[
        Token::Uint(MESSAGE_TYPE_SEND_TO_HUB.into()),
        Token::String(destination_chain),
        Token::Bytes(abi_payload),
    ]);

    let payload_hash: [u8; 32] = Keccak256::digest(abi_payload).into();

    Ok(payload_hash.into())
}

fn get_its_hub_call_params(
    event: &TransactionEvents,
) -> Result<TupleData, Box<dyn std::error::Error>> {
    let payload = get_payload_from_contract_call_event(event)?;

    let its_send_to_hub_signature = TupleTypeSignature::try_from(vec![
        (ClarityName::from("type"), TypeSignature::UIntType),
        (
            ClarityName::from("destination-chain"),
            TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                BufferLength::try_from(18u32)?,
            ))),
        ),
        (
            ClarityName::from("payload"),
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                10240u32,
            )?)),
        ),
    ])?;

    let its_hub_value = Value::try_deserialize_bytes(
        &payload,
        &TypeSignature::TupleType(its_send_to_hub_signature),
        true,
    )?
    .expect_tuple()?;

    Ok(its_hub_value)
}

fn get_payload_from_contract_call_event(
    event: &TransactionEvents,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let contract_log = event.contract_log.as_ref().ok_or(Error::PropertyEmpty)?;

    let contract_call_signature = TupleTypeSignature::try_from(vec![(
        ClarityName::from("payload"),
        TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
            10240u32,
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
        .expect_buff(10240)?;

    Ok(payload)
}

fn get_its_interchain_transfer_abi_payload(
    payload: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let tuple_type_signature = TupleTypeSignature::try_from(vec![
        (
            ClarityName::from("token-id"),
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                32u32,
            )?)),
        ),
        (
            ClarityName::from("source-address"),
            TypeSignature::PrincipalType,
        ),
        (
            ClarityName::from("destination-address"),
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                100u32,
            )?)),
        ),
        (ClarityName::from("amount"), TypeSignature::UIntType),
        (
            ClarityName::from("data"),
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                1024u32,
            )?)),
        ),
    ])?;

    let mut original_value = Value::try_deserialize_bytes(
        &payload,
        &TypeSignature::TupleType(tuple_type_signature),
        true,
    )?
    .expect_tuple()?;

    let abi_payload = encode(&[
        Token::Uint(MESSAGE_TYPE_INTERCHAIN_TRANSFER.into()),
        Token::FixedBytes(
            original_value
                .data_map
                .remove("token-id")
                .ok_or(Error::InvalidCall)?
                .expect_buff(32)?,
        ),
        Token::Bytes(
            original_value
                .data_map
                .remove("source-address")
                .ok_or(Error::InvalidCall)?
                .expect_principal()?
                .serialize_to_vec(),
        ),
        Token::Bytes(
            original_value
                .data_map
                .remove("destination-address")
                .ok_or(Error::InvalidCall)?
                .expect_buff(100)?,
        ),
        Token::Uint(
            original_value
                .data_map
                .remove("amount")
                .ok_or(Error::InvalidCall)?
                .expect_u128()?
                .into(),
        ),
        Token::Bytes(
            original_value
                .data_map
                .remove("data")
                .ok_or(Error::InvalidCall)?
                .expect_buff(1024)?,
        ),
    ]);

    Ok(abi_payload)
}

fn get_its_deploy_interchain_token_abi_payload(
    payload: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let tuple_type_signature = TupleTypeSignature::try_from(vec![
        (
            ClarityName::from("token-id"),
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                32u32,
            )?)),
        ),
        (
            ClarityName::from("name"),
            TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                BufferLength::try_from(32u32)?,
            ))),
        ),
        (
            ClarityName::from("symbol"),
            TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                BufferLength::try_from(32u32)?,
            ))),
        ),
        (ClarityName::from("decimals"), TypeSignature::UIntType),
        (
            ClarityName::from("minter"),
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                200u32,
            )?)),
        ),
    ])?;

    let mut original_value = Value::try_deserialize_bytes(
        &payload,
        &TypeSignature::TupleType(tuple_type_signature),
        true,
    )?
    .expect_tuple()?;

    let abi_payload = encode(&[
        Token::Uint(MESSAGE_TYPE_DEPLOY_INTERCHAIN_TOKEN.into()),
        Token::FixedBytes(
            original_value
                .data_map
                .remove("token-id")
                .ok_or(Error::InvalidCall)?
                .expect_buff(32)?,
        ),
        Token::String(
            original_value
                .data_map
                .remove("name")
                .ok_or(Error::InvalidCall)?
                .expect_ascii()?,
        ),
        Token::String(
            original_value
                .data_map
                .remove("symbol")
                .ok_or(Error::InvalidCall)?
                .expect_ascii()?,
        ),
        Token::Uint(
            original_value
                .data_map
                .remove("decimals")
                .ok_or(Error::InvalidCall)?
                .expect_u128()?
                .into(),
        ),
        Token::Bytes(
            original_value
                .data_map
                .remove("minter")
                .ok_or(Error::InvalidCall)?
                .expect_buff(200)?,
        ),
    ]);

    Ok(abi_payload)
}

fn get_its_deploy_token_manager_payload(
    payload: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let tuple_type_signature = TupleTypeSignature::try_from(vec![
        (
            ClarityName::from("token-id"),
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                32u32,
            )?)),
        ),
        (
            ClarityName::from("token-manager-type"),
            TypeSignature::UIntType,
        ),
        (
            ClarityName::from("params"),
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                1024u32,
            )?)),
        ),
    ])?;

    let mut original_value = Value::try_deserialize_bytes(
        &payload,
        &TypeSignature::TupleType(tuple_type_signature),
        true,
    )?
    .expect_tuple()?;

    let abi_payload = encode(&[
        Token::Uint(MESSAGE_TYPE_DEPLOY_TOKEN_MANAGER.into()),
        Token::FixedBytes(
            original_value
                .data_map
                .remove("token-id")
                .ok_or(Error::InvalidCall)?
                .expect_buff(32)?,
        ),
        Token::Uint(
            original_value
                .data_map
                .remove("token-manager-type")
                .ok_or(Error::InvalidCall)?
                .expect_u128()?
                .into(),
        ),
        Token::Bytes(
            original_value
                .data_map
                .remove("params")
                .ok_or(Error::InvalidCall)?
                .expect_buff(1024)?,
        ),
    ]);

    Ok(abi_payload)
}

pub async fn its_verify_contract_code(
    event: &TransactionEvents,
    http_client: &Client,
    reference_native_interchain_token_code: &String,
    reference_token_manager_code: &String,
) -> Result<bool, Box<dyn std::error::Error>> {
    let (payload, verify_type) = get_its_verify_call_params(event)?;

    match verify_type.as_str() {
        VERIFY_INTERCHAIN_TOKEN => {
            return its_verify_interchain_token(
                payload,
                http_client,
                reference_native_interchain_token_code,
            )
            .await;
        }
        VERIFY_TOKEN_MANAGER => {
            return its_verify_token_manager(payload, http_client, reference_token_manager_code)
                .await;
        }
        _ => {}
    }

    Ok(false)
}

fn get_its_verify_call_params(
    event: &TransactionEvents,
) -> Result<(Vec<u8>, String), Box<dyn std::error::Error>> {
    let payload = get_payload_from_contract_call_event(event)?;

    let verify_type_signature = TupleTypeSignature::try_from(vec![(
        ClarityName::from("type"),
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
            BufferLength::try_from(23u32)?,
        ))),
    )])?;

    let verify_type = Value::try_deserialize_bytes(
        &payload,
        &TypeSignature::TupleType(verify_type_signature),
        true,
    )?
    .expect_tuple()?
    .get_owned("type")?
    .expect_ascii()?;

    Ok((payload, verify_type))
}

async fn its_verify_interchain_token(
    payload: Vec<u8>,
    http_client: &Client,
    reference_native_interchain_token: &String,
) -> Result<bool, Box<dyn std::error::Error>> {
    let tuple_type_signature = TupleTypeSignature::try_from(vec![(
        ClarityName::from("token-address"),
        TypeSignature::PrincipalType,
    )])?;

    let mut value = Value::try_deserialize_bytes(
        &payload,
        &TypeSignature::TupleType(tuple_type_signature),
        true,
    )?
    .expect_tuple()?;

    let token_address = value
        .data_map
        .remove("token-address")
        .ok_or(Error::InvalidCall)?
        .expect_principal()?;

    let token_info = http_client
        .get_contract_info(format!("{}", token_address).as_str())
        .await?;

    Ok(&token_info.source_code == reference_native_interchain_token)
}

async fn its_verify_token_manager(
    payload: Vec<u8>,
    http_client: &Client,
    reference_token_manager_code: &String,
) -> Result<bool, Box<dyn std::error::Error>> {
    let tuple_type_signature = TupleTypeSignature::try_from(vec![(
        ClarityName::from("token-manager-address"),
        TypeSignature::PrincipalType,
    )])?;

    let mut value = Value::try_deserialize_bytes(
        &payload,
        &TypeSignature::TupleType(tuple_type_signature),
        true,
    )?
    .expect_tuple()?;

    let token_manager_address = value
        .data_map
        .remove("token-manager-address")
        .ok_or(Error::InvalidCall)?
        .expect_principal()?;

    let token_manager_info = http_client
        .get_contract_info(format!("{}", token_manager_address).as_str())
        .await?;

    Ok(&token_manager_info.source_code == reference_token_manager_code)
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::voting::Vote;
    use router_api::ChainName;
    use tokio::test as async_test;

    use crate::handlers::stacks_verify_msg::Message;
    use crate::stacks::http_client::Client;
    use crate::stacks::http_client::{
        ContractLog, ContractLogValue, Transaction, TransactionEvents,
    };
    use crate::stacks::verifier::verify_message;

    // test verify message its hub
    #[async_test]
    async fn should_not_verify_its_hub_interchain_transfer_invalid_payload_hash() {
        let (source_chain, gateway_address, its_address, tx, mut msg) =
            get_matching_its_hub_interchain_transfer_msg_and_tx();

        msg.payload_hash = "0xaa38573718f5cd6d7e5a90adcdebd28b097f99574ad6febffea9a40adb17f4aa"
            .parse()
            .unwrap();

        assert_eq!(
            verify_message(
                &source_chain,
                &gateway_address,
                &its_address,
                &tx,
                &msg,
                &Client::faux(),
                &"native_interchain_token_code".to_string(),
                &"token_manager_code".to_string()
            )
            .await,
            Vote::NotFound
        );
    }

    #[async_test]
    async fn should_verify_msg_its_hub_interchain_transfer() {
        let (source_chain, gateway_address, its_address, tx, msg) =
            get_matching_its_hub_interchain_transfer_msg_and_tx();

        assert_eq!(
            verify_message(
                &source_chain,
                &gateway_address,
                &its_address,
                &tx,
                &msg,
                &Client::faux(),
                &"native_interchain_token_code".to_string(),
                &"token_manager_code".to_string()
            )
            .await,
            Vote::SucceededOnChain
        );
    }

    #[async_test]
    async fn should_not_verify_its_hub_deploy_interchain_token_invalid_payload_hash() {
        let (source_chain, gateway_address, its_address, tx, mut msg) =
            get_matching_its_hub_deploy_interchain_token_msg_and_tx();

        msg.payload_hash = "0xaa38573718f5cd6d7e5a90adcdebd28b097f99574ad6febffea9a40adb17f4aa"
            .parse()
            .unwrap();

        assert_eq!(
            verify_message(
                &source_chain,
                &gateway_address,
                &its_address,
                &tx,
                &msg,
                &Client::faux(),
                &"native_interchain_token_code".to_string(),
                &"token_manager_code".to_string()
            )
            .await,
            Vote::NotFound
        );
    }

    #[async_test]
    async fn should_verify_msg_its_hub_deploy_interchain_token() {
        let (source_chain, gateway_address, its_address, tx, msg) =
            get_matching_its_hub_deploy_interchain_token_msg_and_tx();

        assert_eq!(
            verify_message(
                &source_chain,
                &gateway_address,
                &its_address,
                &tx,
                &msg,
                &Client::faux(),
                &"native_interchain_token_code".to_string(),
                &"token_manager_code".to_string()
            )
            .await,
            Vote::SucceededOnChain
        );
    }

    #[async_test]
    async fn should_not_verify_its_hub_deploy_token_manager_invalid_payload_hash() {
        let (source_chain, gateway_address, its_address, tx, mut msg) =
            get_matching_its_hub_deploy_token_manager_msg_and_tx();

        msg.payload_hash = "0xaa38573718f5cd6d7e5a90adcdebd28b097f99574ad6febffea9a40adb17f4aa"
            .parse()
            .unwrap();

        assert_eq!(
            verify_message(
                &source_chain,
                &gateway_address,
                &its_address,
                &tx,
                &msg,
                &Client::faux(),
                &"native_interchain_token_code".to_string(),
                &"token_manager_code".to_string()
            )
            .await,
            Vote::NotFound
        );
    }

    #[async_test]
    async fn should_verify_msg_its_hub_deploy_token_manager() {
        let (source_chain, gateway_address, its_address, tx, msg) =
            get_matching_its_hub_deploy_token_manager_msg_and_tx();

        assert_eq!(
            verify_message(
                &source_chain,
                &gateway_address,
                &its_address,
                &tx,
                &msg,
                &Client::faux(),
                &"native_interchain_token_code".to_string(),
                &"token_manager_code".to_string()
            )
            .await,
            Vote::SucceededOnChain
        );
    }

    // test its_verify_contract_code
    // TODO:

    fn get_matching_its_hub_interchain_transfer_msg_and_tx(
    ) -> (ChainName, String, String, Transaction, Message) {
        let source_chain = "stacks";
        let gateway_address = "SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.axelar-gateway";
        let its_address = "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.interchain-token-service";
        let tx_id = "0xee0049faf8dde5507418140ed72bd64f73cc001b08de98e0c16a3a8d9f2c38cf"
            .parse()
            .unwrap();

        let msg = Message {
            tx_id,
            event_index: 1,
            source_address: its_address.to_string(),
            destination_chain: "axelar".parse().unwrap(),
            destination_address: "cosmwasm".to_string(),
            payload_hash: "0x99cdb5935274c6a59d3ce9cd6c47b58acc0ef461d6b3cab7162c2842c182b94a"
                .parse()
                .unwrap(),
        };

        let wrong_event = TransactionEvents {
            event_index: 0,
            tx_id: tx_id.to_string(),
            contract_log: None,
        };

        /*
            payload is:
            {
                type: u3,
                destination-chain: "ethereum",
                payload: {
                    type: u0,
                    token-id: 0x753306c46380848b5189cd9db90107b15d25decccd93dcb175c0098958f18b6f,
                    source-address: ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM,
                    destination-address: 0x00,
                    amount: u100000,
                    data: 0x00
                }
            }
        */
        let event = TransactionEvents {
            event_index: 1,
            tx_id: tx_id.to_string(),
            contract_log: Some(ContractLog {
                contract_id: gateway_address.to_string(),
                topic: "print".to_string(),
                value: ContractLogValue {
                    hex: "0x0c000000061164657374696e6174696f6e2d636861696e0d000000066178656c61721c64657374696e6174696f6e2d636f6e74726163742d616464726573730d00000008636f736d7761736d077061796c6f616402000000f20c000000031164657374696e6174696f6e2d636861696e0d00000008657468657265756d077061796c6f616402000000ab0c0000000606616d6f756e7401000000000000000000000000000186a004646174610200000001001364657374696e6174696f6e2d616464726573730200000001000e736f757263652d61646472657373051a6d78de7b0625dfbfc16c3a8a5735f6dc3dc3f2ce08746f6b656e2d69640200000020753306c46380848b5189cd9db90107b15d25decccd93dcb175c0098958f18b6f04747970650100000000000000000000000000000000047479706501000000000000000000000000000000030c7061796c6f61642d6861736802000000203dc0763c57c9c7912d2c072718e6ef2ae2d595ce2da31d8b248205d67ad7c3ab0673656e646572061a6d78de7b0625dfbfc16c3a8a5735f6dc3dc3f2ce18696e746572636861696e2d746f6b656e2d7365727669636504747970650d0000000d636f6e74726163742d63616c6c".to_string(),
                }
            }),
        };

        let transaction = Transaction {
            tx_id,
            nonce: 1,
            sender_address: "whatever".to_string(),
            tx_status: "success".to_string(),
            events: vec![wrong_event, event],
        };

        (
            source_chain.parse().unwrap(),
            gateway_address.to_string(),
            its_address.to_string(),
            transaction,
            msg,
        )
    }

    fn get_matching_its_hub_deploy_interchain_token_msg_and_tx(
    ) -> (ChainName, String, String, Transaction, Message) {
        let source_chain = "stacks";
        let gateway_address = "SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.axelar-gateway";
        let its_address = "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.interchain-token-service";
        let tx_id = "0xee0049faf8dde5507418140ed72bd64f73cc001b08de98e0c16a3a8d9f2c38cf"
            .parse()
            .unwrap();

        let msg = Message {
            tx_id,
            event_index: 1,
            source_address: its_address.to_string(),
            destination_chain: "axelar".parse().unwrap(),
            destination_address: "0x00".to_string(),
            payload_hash: "0x63b56229fc520914aa0f690e136517fceae159a49082f5f18f866a9ba5e3ce15"
                .parse()
                .unwrap(),
        };

        let wrong_event = TransactionEvents {
            event_index: 0,
            tx_id: tx_id.to_string(),
            contract_log: None,
        };

        /*
            payload is:
            {
                type: u3,
                destination-chain: "ethereum",
                payload: {
                    type: u1,
                    token-id: 0x42fad3435446674f88b47510fe7d2d144c8867c405d4933007705db85f37ded5,
                    name: "sample",
                    symbol: "sample",
                    decimals: u6,
                    minter: 0x00
                }
            }
        */
        let event = TransactionEvents {
            event_index: 1,
            tx_id: tx_id.to_string(),
            contract_log: Some(ContractLog {
                contract_id: gateway_address.to_string(),
                topic: "print".to_string(),
                value: ContractLogValue {
                    hex: "0x0c000000061164657374696e6174696f6e2d636861696e0d000000066178656c61721c64657374696e6174696f6e2d636f6e74726163742d616464726573730d0000000430783030077061796c6f616402000000d90c000000031164657374696e6174696f6e2d636861696e0d00000008657468657265756d077061796c6f616402000000920c0000000608646563696d616c730100000000000000000000000000000006066d696e746572020000000100046e616d650d0000000673616d706c650673796d626f6c0d0000000673616d706c6508746f6b656e2d69640200000020563dc3698c0f2c5adf375ff350bb54ecf86d2be109e3aacaf38111cdf171df7804747970650100000000000000000000000000000001047479706501000000000000000000000000000000030c7061796c6f61642d6861736802000000207bcf62a3e8aed07d1eb704a1c4b142de9c1f429d2a6cf835c3347763ae8e05ab0673656e646572061a6d78de7b0625dfbfc16c3a8a5735f6dc3dc3f2ce18696e746572636861696e2d746f6b656e2d7365727669636504747970650d0000000d636f6e74726163742d63616c6c".to_string(),
                }
            }),
        };

        let transaction = Transaction {
            tx_id,
            nonce: 1,
            sender_address: "whatever".to_string(),
            tx_status: "success".to_string(),
            events: vec![wrong_event, event],
        };

        (
            source_chain.parse().unwrap(),
            gateway_address.to_string(),
            its_address.to_string(),
            transaction,
            msg,
        )
    }

    fn get_matching_its_hub_deploy_token_manager_msg_and_tx(
    ) -> (ChainName, String, String, Transaction, Message) {
        let source_chain = "stacks";
        let gateway_address = "SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.axelar-gateway";
        let its_address = "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.interchain-token-service";
        let tx_id = "0xee0049faf8dde5507418140ed72bd64f73cc001b08de98e0c16a3a8d9f2c38cf"
            .parse()
            .unwrap();

        let msg = Message {
            tx_id,
            event_index: 1,
            source_address: its_address.to_string(),
            destination_chain: "axelar".parse().unwrap(),
            destination_address: "cosmwasm".to_string(),
            payload_hash: "0x617076bb0067f463de653c1d16e4037f2cfb59c383820351e5b8bd2ca9d50948"
                .parse()
                .unwrap(),
        };

        let wrong_event = TransactionEvents {
            event_index: 0,
            tx_id: tx_id.to_string(),
            contract_log: None,
        };

        /*
            payload is:
            {
                type: u3,
                destination-chain: "ethereum",
                payload: {
                    type: u2,
                    token-id: 0xc99a1f0a4b46456129d86b37f580af16fea20eeaf7e73628547c10f6799b90b0,
                    token-manager-type: u2,
                    params: 0x00
                }
            }
        */
        let event = TransactionEvents {
            event_index: 1,
            tx_id: tx_id.to_string(),
            contract_log: Some(ContractLog {
                contract_id: gateway_address.to_string(),
                topic: "print".to_string(),
                value: ContractLogValue {
                    hex: "0x0c000000061164657374696e6174696f6e2d636861696e0d000000066178656c61721c64657374696e6174696f6e2d636f6e74726163742d616464726573730d00000008636f736d7761736d077061796c6f616402000000c10c000000031164657374696e6174696f6e2d636861696e0d00000008657468657265756d077061796c6f6164020000007a0c0000000406706172616d7302000000010008746f6b656e2d69640200000020c99a1f0a4b46456129d86b37f580af16fea20eeaf7e73628547c10f6799b90b012746f6b656e2d6d616e616765722d74797065010000000000000000000000000000000204747970650100000000000000000000000000000002047479706501000000000000000000000000000000030c7061796c6f61642d6861736802000000209ce89d392d43333d269dd9f234e765ded79db1ba895e8b2e3d6d8f936cae57320673656e646572061a6d78de7b0625dfbfc16c3a8a5735f6dc3dc3f2ce18696e746572636861696e2d746f6b656e2d7365727669636504747970650d0000000d636f6e74726163742d63616c6c".to_string(),
                }
            }),
        };

        let transaction = Transaction {
            tx_id,
            nonce: 1,
            sender_address: "whatever".to_string(),
            tx_status: "success".to_string(),
            events: vec![wrong_event, event],
        };

        (
            source_chain.parse().unwrap(),
            gateway_address.to_string(),
            its_address.to_string(),
            transaction,
            msg,
        )
    }
}
