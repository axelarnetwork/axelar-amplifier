use std::collections::HashMap;

use crate::types::Hash;
use k256::sha2::Sha256;
use sha3::Digest;
use xrpl_http_client::{client::Client, Memo, Transaction::Payment, TxRequest, TxResponse};
use axelar_wasm_std::voting::Vote;

use crate::handlers::xrpl_verify_msg::{Message, XRPLAddress};

pub fn verify_message(
    gateway_address: &XRPLAddress,
    tx_response: &TxResponse,
    message: &Message,
) -> Vote {
    match &tx_response.tx {
        Payment(payment_tx) if payment_tx.destination == gateway_address.0 && payment_tx.amount == message.amount && matches!(payment_tx.clone().common.memos, Some(_memos)) && verify_memos(payment_tx.clone().common.memos.unwrap(), message) => {
            Vote::SucceededOnChain
        },
        _ => Vote::NotFound,
    }
}

pub fn verify_memos(memos: Vec<Memo>, message: &Message) -> bool {
    let memo_kv: HashMap<String, String> = memos
        .into_iter()
        .filter(|m| m.memo_type.is_some() && m.memo_data.is_some())
        .map(|m| (m.memo_type.unwrap(), m.memo_data.unwrap()))
        .collect();

    // TODO: how are memo types converted to strings here, maybe they need hex decoding?
    memo_kv.get("destination_address") == Some(&message.destination_address)
    && memo_kv.get("destination_chain") == Some(&message.destination_chain.to_string())
    && (memo_kv.get("payload_hash") == Some(&message.payload_hash.to_string()) || (memo_kv.contains_key("payload") && verify_payload(memo_kv.get("payload").unwrap(), &message.payload_hash)))
}

// TODO: is ethers Hash type ok here?
pub fn verify_payload(payload: &String, payload_hash: &Hash) -> bool {
    Sha256::digest(payload) == payload_hash.to_fixed_bytes().into()
}