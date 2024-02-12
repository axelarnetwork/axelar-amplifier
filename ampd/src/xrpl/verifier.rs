use std::collections::HashMap;
use std::str::FromStr;

use crate::types::Hash;
use connection_router::state::ChainName;
use k256::sha2::Sha256;
use sha3::Digest;
use xrpl_http_client::ResultCategory;
use xrpl_http_client::{Memo, Transaction::Payment, Transaction};
use axelar_wasm_std::voting::Vote;

use crate::handlers::xrpl_verify_msg::Message;
use crate::xrpl::types::XRPLAddress;

pub fn verify_message(
    multisig_address: &XRPLAddress,
    tx: &Transaction,
    message: &Message,
) -> Vote {
    if is_validated_tx(tx) && (is_valid_multisig_tx(tx, multisig_address, message) || is_valid_deposit_tx(tx, multisig_address, message)) {
        if is_successful_tx(tx) {
            Vote::SucceededOnChain
        } else {
            Vote::FailedOnChain
        }
    } else {
        Vote::NotFound
    }
}

pub fn is_validated_tx(tx: &Transaction) -> bool {
    matches!(tx.common().validated, Some(true))
}

pub fn is_valid_multisig_tx(tx: &Transaction, multisig_address: &XRPLAddress, message: &Message) -> bool {
    tx.common().account == multisig_address.0 && message.source_address == *multisig_address && message.destination_chain == ChainName::from_str("XRPL").unwrap()
}

pub fn is_valid_deposit_tx(tx: &Transaction, multisig_address: &XRPLAddress, message: &Message) -> bool {
    if let Payment(payment_tx) = &tx {
        if let Some(memos) = payment_tx.clone().common.memos {
            return payment_tx.destination == multisig_address.0 && message.source_address.0 == tx.common().account && verify_memos(memos, message);
        }
    }
    return false;
}

pub fn is_successful_tx(tx: &Transaction) -> bool {
    if let Some(meta) = &tx.common().meta {
        return meta.transaction_result.category() == ResultCategory::Tes;
    }
    return false;
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