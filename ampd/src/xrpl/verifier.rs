use std::collections::HashMap;
use std::str::FromStr;

use serde::Serialize;
use connection_router_api::ChainName;
use xrpl_http_client::{Amount, ResultCategory};
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
    if message.event_index == 0 && is_validated_tx(tx) && (is_valid_multisig_tx(tx, multisig_address, message) || is_valid_deposit_tx(tx, multisig_address, message)) {
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
            return payment_tx.destination == multisig_address.0 && message.source_address.0 == tx.common().account && verify_memos(payment_tx.amount.clone(), memos, message);
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

fn remove_0x_prefix(s: String) -> String {
    if s.starts_with("0x") {
        s[2..].to_string()
    } else {
        s
    }
}

pub fn verify_memos(amount: Amount, memos: Vec<Memo>, message: &Message) -> bool {
    let memo_kv: HashMap<String, String> = memos
        .into_iter()
        .filter(|m| m.memo_type.is_some() && m.memo_data.is_some())
        .map(|m| (String::from_utf8(hex::decode(m.memo_type.unwrap()).unwrap()).unwrap(), m.memo_data.unwrap()))
        .collect();

    || -> Option<bool> {
        let (token , amount) = match amount {
            Amount::Issued(a) => (a.currency, a.value),
            Amount::Drops(a) => ("XRP".to_string(), a),
        };

        let expected_payload = ethers::abi::encode(&vec![
            ethers::abi::Token::String(token),
            ethers::abi::Token::String(amount),
            ethers::abi::Token::FixedBytes(hex::decode(remove_0x_prefix(memo_kv.get("payload_hash")?.clone())).ok()?),
        ]);
        let expected_payload_hash = ethers::utils::keccak256(expected_payload.clone());

        Some(memo_kv.get("destination_address") == Some(&remove_0x_prefix(message.destination_address.clone()).to_uppercase())
        && memo_kv.get("destination_chain") == Some(&hex::encode_upper(message.destination_chain.to_string()))
        && *message.payload_hash.to_fixed_bytes().to_vec() == expected_payload_hash)
    }().unwrap_or(false)
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::xrpl::{types::XRPLAddress, verifier::verify_memos};
    use ethers::types::TxHash;
    use xrpl_http_client::{Amount, Memo};
    use crate::handlers::xrpl_verify_msg::Message;
    use connection_router_api::ChainName;

    #[test]
    fn test_verify_memos() {
        let memos = vec![
            Memo {
                memo_type: Some("64657374696E6174696F6E5F61646472657373".to_string()),
                memo_data: Some("592639C10223C4EC6C0FFC670E94D289A25DD1AD".to_string()),
                memo_format: None
            },
            Memo {
                memo_type: Some("64657374696E6174696F6E5F636861696E".to_string()),
                memo_data: Some("657468657265756D".to_string()),
                memo_format: None
            },
            Memo {
                memo_type: Some("7061796C6F61645F68617368".to_string()),
                memo_data: Some("4F246000525114CC0CC261973D12E9A1C53B7AA295DF41FA6A6BFD00045BF0E6".to_string()),
                memo_format: None
            }
        ];
        let message = Message {
            tx_id: crate::xrpl::types::TransactionId("1c6019555252bcb7bca95237d333a6c473112d6396d4f151a4a1c1f00f04f8f3".to_string()),
            event_index: 14,
            source_address: XRPLAddress("raNVNWvhUQzFkDDTdEw3roXRJfMJFVJuQo".to_string()),
            destination_address: "0x592639c10223C4EC6C0ffc670e94d289A25DD1ad".to_string(),
            destination_chain: ChainName::from_str("ethereum").unwrap(),
            payload_hash: TxHash(hex::decode("25b99c1524e2467c7d30cdaae191d6ce6fa6e7fa73e8cb561d2dc93178f1e083").unwrap().to_vec().try_into().unwrap())
        };
        assert!(verify_memos(Amount::Drops("1000000".to_string()), memos, &message));
    }
}
