use std::collections::HashMap;

use sha3::{Digest, Keccak256};
use xrpl_http_client::{Amount, ResultCategory};
use xrpl_http_client::{Memo, Transaction::Payment, Transaction};
use axelar_wasm_std::voting::Vote;
use xrpl_types::msg::{XRPLUserMessage, XRPLProverMessage, XRPLMessage};
use xrpl_types::types::{XRPLAccountId, XRPLPaymentAmount, XRPLToken};

fn parse_memos(memos: Vec<Memo>) -> HashMap<String, String> {
    memos
        .into_iter()
        .filter(|m| m.memo_type.is_some() && m.memo_data.is_some())
        .map(|m| (String::from_utf8(hex::decode(m.memo_type.unwrap()).expect("Memo value should be hex")).ok(), m.memo_data))
        .filter_map(|(k, v)| {
            match (k, v) {
                (Some(k), Some(v)) => Some((k, v)),
                _ => None,
            }
        })
        .collect::<HashMap<String, String>>()
}

pub fn verify_message(
    multisig_address: &XRPLAccountId,
    tx: &Transaction,
    message: &XRPLMessage,
) -> Vote {
    let memos = parse_memos(tx.common().memos.clone().unwrap_or(vec![]));
    let is_valid_message = match message {
        XRPLMessage::ProverMessage(prover_message) => is_valid_prover_message(tx, multisig_address, prover_message, memos),
        XRPLMessage::UserMessage(user_message) => is_valid_user_message(tx, multisig_address, user_message, memos),
    };

    if is_validated_tx(tx) && is_valid_message {
        if is_successful_tx(tx) {
            Vote::SucceededOnChain
        } else {
            Vote::FailedOnChain
        }
    } else {
        Vote::NotFound
    }
}

// sanity check
pub fn is_validated_tx(tx: &Transaction) -> bool {
    matches!(tx.common().validated, Some(true))
}

pub fn is_valid_prover_message(
    tx: &Transaction,
    multisig_address: &XRPLAccountId,
    message: &XRPLProverMessage,
    memos: HashMap<String, String>
) -> bool {
    tx.common().account == multisig_address.to_string() && memos.get("unsigned_tx_hash") == Some(&message.unsigned_tx_hash.to_string().to_uppercase())
}

pub fn is_valid_user_message(
    tx: &Transaction,
    multisig_address: &XRPLAccountId,
    message: &XRPLUserMessage,
    memos: HashMap<String, String>
) -> bool {
    if let Payment(payment_tx) = &tx {
        let tx_amount = payment_tx.amount.clone();
        match tx.common().meta.clone() {
            Some(tx_meta) => {
                if tx_meta.delivered_amount != Some(tx_amount.clone()) {
                    return false;
                }
            }
            None => return false,
        }

        return payment_tx.destination == multisig_address.to_string()
            && message.source_address.to_string() == tx.common().account
            && verify_amount(tx_amount, message)
            && verify_memos(memos, message)
            && payment_tx.flags.is_empty(); // TODO: whitelist specific flags
    }
    return false;
}

pub fn is_successful_tx(tx: &Transaction) -> bool {
    if let Some(meta) = &tx.common().meta {
        return meta.transaction_result.category() == ResultCategory::Tes;
    }
    return false;
}

fn remove_0x_prefix(s: String) -> String {
    if s.starts_with("0x") {
        s[2..].to_string()
    } else {
        s
    }
}

pub fn verify_amount(amount: Amount, message: &XRPLUserMessage) -> bool {
    || -> Option<bool> {
        let amount = match amount {
            Amount::Issued(a) => XRPLPaymentAmount::Issued(
                XRPLToken {
                    issuer: a.issuer.try_into().ok()?,
                    currency: a.currency.try_into().ok()?,
                },
                a.value.try_into().ok()?
            ),
            Amount::Drops(a) => XRPLPaymentAmount::Drops(a.parse().ok()?),
        };

        Some(amount == message.amount)
    }().unwrap_or(false)
}

pub fn verify_memos(memos: HashMap<String, String>, message: &XRPLUserMessage) -> bool {
    || -> Option<bool> {
        let payload_hash: Option<[u8; 32]> = match memos.get("payload_hash").clone() {
            Some(hash) => hex::decode(&remove_0x_prefix(hash.clone())).ok()?.try_into().ok(),
            None => match memos.get("payload") {
                Some(payload) => Keccak256::digest(hex::decode(&remove_0x_prefix(payload.clone())).ok()?).as_slice().try_into().ok(),
                None => None,
            },
        };

        Some(
            memos.get("destination_address")? == &remove_0x_prefix(message.destination_address.to_string()).to_uppercase()
            && memos.get("destination_chain")? == &hex::encode_upper(message.destination_chain.to_string())
            && payload_hash == message.payload_hash
        )
    }().unwrap_or(false)
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::xrpl::verifier::{parse_memos, verify_memos};
    use axelar_wasm_std::nonempty;
    use cosmwasm_std::HexBinary;
    use xrpl_http_client::Memo;
    use xrpl_types::msg::XRPLUserMessage;
    use xrpl_types::types::{TxHash, XRPLAccountId, XRPLPaymentAmount};
    use router_api::ChainName;

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
        let user_message = XRPLUserMessage {
            tx_id: TxHash::new([0; 32]),
            source_address: XRPLAccountId::from_str("raNVNWvhUQzFkDDTdEw3roXRJfMJFVJuQo").unwrap(),
            destination_address: nonempty::HexBinary::try_from(HexBinary::from_hex("592639c10223C4EC6C0ffc670e94d289A25DD1ad").unwrap()).unwrap(),
            destination_chain: ChainName::from_str("ethereum").unwrap(),
            payload_hash: Some(hex::decode("4F246000525114CC0CC261973D12E9A1C53B7AA295DF41FA6A6BFD00045BF0E6").unwrap().to_vec().try_into().unwrap()),
            amount: XRPLPaymentAmount::Drops(100000),
        };
        assert!(verify_memos(parse_memos(memos), &user_message));
    }
}
