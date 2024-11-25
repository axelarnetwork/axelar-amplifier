use axelar_wasm_std::voting::Vote;
use gmp_gateway::events::{ArchivedCallContract, ArchivedGatewayEvent, GatewayEvent};
use solana_sdk::pubkey::Pubkey;
use solana_transaction_status::{
    option_serializer::OptionSerializer, EncodedConfirmedTransactionWithStatusMeta,
};
use std::str::FromStr;
use std::sync::Arc;
use tracing::error;

use crate::handlers::solana_verify_msg::Message;

impl PartialEq<&Message> for &ArchivedGatewayEvent {
    fn eq(&self, msg: &&Message) -> bool {
        match self {
            ArchivedGatewayEvent::CallContract(ArchivedCallContract {
                sender,
                destination_chain,
                destination_address,
                payload: _,
                payload_hash,
            }) => {
                let Ok(msg_sender) = Pubkey::from_str(msg.source_address.as_str()) else {
                    return false;
                };

                sender == &msg_sender.to_bytes()
                    && msg.destination_chain == destination_chain.as_str()
                    && msg.destination_address == destination_address.as_str()
                    && *payload_hash == msg.payload_hash
            }
            _ => false,
        }
    }
}

pub fn verify_message(
    source_gateway_address: &String,
    tx: Arc<EncodedConfirmedTransactionWithStatusMeta>,
    message: &Message,
) -> Vote {
    let ui_tx = match &tx.transaction.transaction {
        solana_transaction_status::EncodedTransaction::Json(tx) => tx,
        _ => {
            error!("failed to parse solana tx.");
            return Vote::FailedOnChain;
        }
    };

    // NOTE: first signature is always tx_id
    let tx_id = match ui_tx.signatures.first() {
        Some(tx) => tx,
        None => {
            error!("failed to parse solana tx signatures.");
            return Vote::FailedOnChain;
        }
    };

    let tx_meta = match &tx.transaction.meta {
        Some(meta) => meta,
        None => {
            error!(
                tx_id = tx_id,
                "Theres no available tx metadata to parse log messages from."
            );
            return Vote::FailedOnChain;
        }
    };

    let log_messages = match &tx_meta.log_messages {
        OptionSerializer::Some(log) => log,
        _ => {
            error!(tx_id = tx_id, "Theres no log messages in tx.");
            return Vote::FailedOnChain;
        }
    };

    let ui_parsed_msg = match &ui_tx.message {
        solana_transaction_status::UiMessage::Raw(msg) => msg,
        _ => {
            error!(
                tx_id = tx_id,
                "Could not gather tx message for checking account keys."
            );
            return Vote::FailedOnChain;
        }
    };

    match find_first_log_message_match(
        tx_id,
        log_messages,
        message,
        &ui_parsed_msg.account_keys,
        source_gateway_address,
    ) {
        Some(_) => Vote::SucceededOnChain,
        None => Vote::FailedOnChain,
    }
}

// This function iterates over all Solana tx log messages
// trying to find at least one log msg that matches the
// Axelar provided one. For doing that, its necessary to:
//
// 1. Deserialize the tx log message, which contains the gateway event.
// 2. The parsed gateway event from 1 matches the Axelar message.
//
// This function is only intended for use inside this crate
// and its arguments are basically parts of the Solana tx plus
// the Axelar counterpart for verification purposes.
//
// When the first matching log message is found, its index will be returned.
fn find_first_log_message_match(
    tx_id: &str,
    log_messages: &[String],
    message: &Message,
    account_keys: &[String],
    source_gateway_address: &String,
) -> Option<usize> {
    for (i, log) in log_messages.iter().enumerate() {
        match GatewayEvent::parse_log(log) {
            Some(parsed_ev) => {
                let arch_gw_event = parsed_ev.parse();
                let verified = arch_gw_event == message
                    && *tx_id == message.tx_id
                    && account_keys.contains(source_gateway_address);

                if verified {
                    return Some(i);
                }
            }
            None => continue,
        }
    }
    None
}

#[cfg(test)]
mod tests {

    use axelar_rkyv_encoding::rkyv::ser::{serializers::AllocSerializer, Serializer};
    use base64::{engine::general_purpose, Engine};
    use gmp_gateway::{events::CallContract, solana_program::pubkey::Pubkey};

    use std::str::FromStr;

    use router_api::ChainName;

    use super::*;

    #[test]
    fn should_verify_msg_if_correct() {
        let (source_gateway_address, _, tx, msg) = get_matching_msg_and_tx_block();
        assert_eq!(
            Vote::SucceededOnChain,
            verify_message(&source_gateway_address, Arc::new(tx), &msg)
        );
    }

    // Provides a matching [`EncodedConfirmedTransactionWithStatusMeta`] and [`Message`] fixtures for testing.
    // Other tests may slightly modify the above provided test fixtures for generating negative
    // cases.
    fn get_matching_msg_and_tx_block() -> (
        String,
        String,
        EncodedConfirmedTransactionWithStatusMeta,
        Message,
    ) {
        // Common fields among tx and message.
        let tx_id = "3GLo4z4siudHxW1BMHBbkTKy7kfbssNFaxLR5hTjhEXCUzp2Pi2VVwybc1s96pEKjRre7CcKKeLhni79zWTNUseP".to_string();
        let destination_chain = "eth".to_string();
        let destination_address = "0x0".to_string();
        let payload: Vec<u8> = Vec::new();
        let payload_hash: [u8; 32] = [0; 32];
        let source_gateway_address: String = "sol_gateway_addr".to_string();
        let source_pubkey = Pubkey::from([0; 32]);
        let source_address = source_pubkey;

        // Code below helps on generating the program log line for adding in the
        // tests/solana_tx.json file and use it as test fixture. See the "logMessages" field
        // on it.

        // println!(
        //     "------> {}",
        //     get_tx_log_message(
        //         source_address.clone(),
        //         destination_chain.clone().into_bytes(),
        //         destination_address.clone().into_bytes(),
        //         payload,
        //         payload_hash
        //     )
        // );

        // We prefer to parse a tx from a json file, as its cleaner than filling types.
        // Changing this "golden file" may result in broken tests.
        let tx: EncodedConfirmedTransactionWithStatusMeta =
            serde_json::from_str(include_str!("tests/solana_tx.json")).unwrap();

        let message = Message {
            tx_id: tx_id.clone(),
            event_index: 0,
            destination_address: destination_address.clone(),
            destination_chain: ChainName::from_str(&destination_chain).unwrap(),
            source_address: source_address.to_string(),
            payload_hash,
        };

        (source_gateway_address, tx_id, tx, message)
    }

    fn get_tx_log_message(
        sender: gmp_gateway::solana_program::pubkey::Pubkey,
        destination_chain: Vec<u8>,
        destination_address: Vec<u8>,
        payload: Vec<u8>,
        payload_hash: [u8; 32],
    ) -> String {
        let event = gmp_gateway::events::GatewayEvent::CallContract(CallContract {
            sender: sender.to_bytes(),
            destination_chain: String::from_utf8(destination_chain).unwrap(),
            destination_address: String::from_utf8(destination_address).unwrap(),
            payload,
            payload_hash,
        });

        let mut serializer = AllocSerializer::<0>::default();
        serializer.serialize_value(&event).unwrap();
        let bytes = serializer.into_serializer().into_inner();
        let event_data_b64 = general_purpose::STANDARD.encode(bytes);
        let mut log_message = "Program data: ".to_string();
        log_message.push_str(&event_data_b64);
        log_message
    }

    #[test]
    fn should_not_verify_msg_if_tx_id_does_not_match() {
        let (source_gateway_address, _, tx, mut msg) = get_matching_msg_and_tx_block();
        msg.tx_id = "wrong_tx_id".to_string();
        assert_eq!(
            Vote::FailedOnChain,
            verify_message(&source_gateway_address, Arc::new(tx), &msg)
        );
    }

    #[ignore = "We are not checking the event index in production code."]
    #[test]
    fn should_not_verify_msg_if_event_index_does_not_match() {
        let (gateway_address, _, tx, mut msg) = get_matching_msg_and_tx_block();
        msg.event_index = rand::random::<u64>();
        assert_eq!(
            Vote::NotFound,
            verify_message(&gateway_address, Arc::new(tx), &msg)
        );
    }

    #[test]
    fn should_not_verify_msg_if_destination_chain_does_not_match() {
        let (gateway_address, _, tx, mut msg) = get_matching_msg_and_tx_block();
        msg.destination_chain = ChainName::from_str("badchain").unwrap();
        assert_eq!(
            Vote::FailedOnChain,
            verify_message(&gateway_address, Arc::new(tx), &msg)
        );
    }

    #[test]
    fn should_not_verify_msg_if_source_address_does_not_match() {
        let (source_gateway_address, _, tx, mut msg) = get_matching_msg_and_tx_block();
        msg.source_address = Pubkey::from([13; 32]).to_string();
        assert_eq!(
            Vote::FailedOnChain,
            verify_message(&source_gateway_address, Arc::new(tx), &msg)
        );
    }

    #[test]
    fn should_not_verify_msg_if_destination_address_does_not_match() {
        let (gateway_address, _, tx, mut msg) = get_matching_msg_and_tx_block();
        msg.destination_address = "bad_address".to_string();
        assert_eq!(
            Vote::FailedOnChain,
            verify_message(&gateway_address, Arc::new(tx), &msg)
        );
    }

    #[test]
    fn should_not_verify_msg_if_payload_hash_does_not_match() {
        let (gateway_address, _, tx, mut msg) = get_matching_msg_and_tx_block();
        msg.payload_hash = [1; 32];
        assert_eq!(
            Vote::FailedOnChain,
            verify_message(&gateway_address, Arc::new(tx), &msg)
        );
    }

    #[test]
    fn find_first_log_message_match_should_iterate_until_valid_match_found() {
        let (gateway_address, tx_id, _, msg) = get_matching_msg_and_tx_block();

        let log_messages = vec![
            bad_tx_log_message(),
            not_matching_tx_log_message(&msg),
            matching_tx_log_message(&msg),
        ];

        assert_eq!(
            Some(2),
            find_first_log_message_match(
                &tx_id,
                &log_messages,
                &msg,
                &[gateway_address.clone()],
                &gateway_address
            )
        );
    }

    fn bad_tx_log_message() -> String {
        "BAD_LOG_MESSAGE".to_string()
    }

    fn not_matching_tx_log_message(msg: &Message) -> String {
        get_tx_log_message(
            Pubkey::from_str(&msg.source_address).unwrap(),
            "abr".as_bytes().to_vec(),
            msg.destination_address.clone().into_bytes(),
            Vec::new(),
            msg.payload_hash,
        ) // changing destination chain.
    }

    fn matching_tx_log_message(msg: &Message) -> String {
        get_tx_log_message(
            Pubkey::from_str(&msg.source_address).unwrap(),
            msg.destination_chain.to_string().into_bytes(),
            msg.destination_address.clone().into_bytes(),
            Vec::new(),
            msg.payload_hash,
        ) // not changing anything. Should match
    }

    #[test]
    fn find_first_log_message_match_should_stop_on_first_valid_match_found() {
        let (gateway_address, tx_id, _, msg) = get_matching_msg_and_tx_block();

        let log_messages = vec![
            not_matching_tx_log_message(&msg),
            matching_tx_log_message(&msg),
            matching_tx_log_message(&msg),
        ];

        assert_eq!(
            Some(1), // index 1
            find_first_log_message_match(
                &tx_id,
                &log_messages,
                &msg,
                &[gateway_address.clone()],
                &gateway_address
            )
        );
    }

    #[test]
    fn find_first_log_message_match_should_return_none_if_not_match() {
        let (gateway_address, tx_id, _, msg) = get_matching_msg_and_tx_block();

        let log_messages = vec![not_matching_tx_log_message(&msg), bad_tx_log_message()];

        assert_eq!(
            None, // index 1
            find_first_log_message_match(
                &tx_id,
                &log_messages,
                &msg,
                &[gateway_address.clone()],
                &gateway_address
            )
        );
    }
}
