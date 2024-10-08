use clarity::vm::ClarityName;
use crate::handlers::stacks_verify_msg::Message;
use crate::stacks::error::Error;
use crate::stacks::http_client::{Transaction, TransactionEvents};
use axelar_wasm_std::voting::Vote;
use clarity::vm::types::{TupleTypeSignature, TypeSignature, Value};

const CONTRACT_CALL_TOPIC: &str = "contract-call";

impl Message {
    fn eq_event(&self, event: &TransactionEvents) -> Result<bool, Box<dyn std::error::Error>> {
        let contract_log = event.contract_log.as_ref().ok_or(Error::PropertyEmpty)?;

        if contract_log.topic != CONTRACT_CALL_TOPIC {
            return Ok(false);
        }

        let tuple_type_signature = TupleTypeSignature::try_from(vec![(
            ClarityName::try_from("sender".to_string())?,
            TypeSignature::PrincipalType,
        )])?;

        let value = Value::try_deserialize_hex(
            contract_log.value.hex.as_str(),
            &TypeSignature::TupleType(tuple_type_signature),
            false,
        )?;

        value.expect_tuple()?;

        Ok(true)
    }
}

fn find_event<'a>(
    transaction: &'a Transaction,
    gateway_address: &String,
    log_index: u32,
) -> Option<&'a TransactionEvents> {
    let event = transaction
        .events
        .iter()
        .find(|el| el.event_index == log_index)?;

    if !event.contract_log.as_ref()?.contract_id.eq(gateway_address) {
        return None;
    }

    Some(event)
}

pub fn verify_message(
    gateway_address: &String,
    transaction: &Transaction,
    message: &Message,
) -> Vote {
    if message.tx_id.to_string() != transaction.tx_id {
        return Vote::NotFound;
    }

    match find_event(transaction, gateway_address, message.event_index) {
        Some(event) if message.eq_event(event).unwrap_or(false) => Vote::SucceededOnChain,
        _ => Vote::NotFound,
    }
}
