use axelar_wasm_std::voting::Vote;
use crate::handlers::stacks_verify_msg::Message;
use crate::stacks::http_client::Transaction;

pub fn verify_message(
    gateway_address: &String,
    transaction: &Transaction,
    message: &Message,
) -> Vote {
    Vote::NotFound // TODO:
}
