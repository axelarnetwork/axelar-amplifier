use std::collections::HashMap;
use std::str::FromStr;

use crate::types::Hash;
use serde::Serialize;
use connection_router::state::ChainName;
use k256::sha2::Sha256;
use serde_json::to_string;
use sha3::Digest;
use xrpl_http_client::ResultCategory;
use xrpl_http_client::{Memo, Transaction::Payment, Transaction};
use axelar_wasm_std::voting::Vote;
use cosmwasm_std::{Uint256, HexBinary};

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

#[derive(Serialize, Debug, PartialEq)]
struct MemoPayload {
    fee: Uint256,
    relayer: String,
    amount: Uint256,
    currency: String,
    payload_hash: HexBinary
}

pub fn verify_memos(memos: Vec<Memo>, message: &Message) -> bool {
    let memo_kv: HashMap<String, String> = memos
        .into_iter()
        .filter(|m| m.memo_type.is_some() && m.memo_data.is_some())
        .map(|m| (m.memo_type.unwrap(), m.memo_data.unwrap()))
        .collect();

    || -> Option<bool> {
        let memo_payload_hash = memo_kv
            .get("payload_hash")
            .cloned()
            .or_else(|| {
                memo_kv.get("payload").map(|p| hex::encode(Sha256::digest(p).to_vec()))
            })?;
        let memo_payload = MemoPayload {
            fee: Uint256::from_str(memo_kv.get("fee")?).ok()?,
            relayer: memo_kv.get("relayer")?.clone(),
            amount: Uint256::from_str(memo_kv.get("amount")?).ok()?,
            currency: memo_kv.get("currency")?.clone(),
            payload_hash: HexBinary::from_hex(memo_payload_hash.as_str()).ok()?
        };
        let memo_hash: [u8; 32] = Sha256::digest(to_string(&memo_payload).ok()?).into();
        Some(memo_kv.get("destination_address") == Some(&message.destination_address)
        && memo_kv.get("destination_chain") == Some(&message.destination_chain.to_string())
        && *message.payload_hash.as_fixed_bytes() == memo_hash)
    }().unwrap_or(false)
}