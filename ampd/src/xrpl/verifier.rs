use sha3::{Digest, Keccak256};
use std::collections::HashMap;

use axelar_wasm_std::voting::Vote;
use xrpl_http_client::Transaction::Payment;
use xrpl_http_client::{Amount, Memo, ResultCategory, Transaction};
use xrpl_types::msg::{XRPLMessage, XRPLProverMessage, XRPLUserMessage};
use xrpl_types::types::{XRPLAccountId, XRPLPaymentAmount, XRPLToken};

fn parse_memos(memos: Vec<Memo>) -> HashMap<String, String> {
    memos
        .into_iter()
        .filter_map(|m| {
            let memo_type = m
                .memo_type
                .and_then(|t| hex::decode(t).ok())
                .and_then(|bytes| String::from_utf8(bytes).ok());

            let memo_data = m.memo_data;
            memo_type.zip(memo_data)
        })
        .collect::<HashMap<String, String>>()
}

pub fn verify_message(
    multisig_address: &XRPLAccountId,
    tx: &Transaction,
    message: &XRPLMessage,
) -> Vote {
    let memos = parse_memos(tx.common().memos.clone().unwrap_or_default());
    let is_valid_message = match message {
        XRPLMessage::ProverMessage(prover_message) => {
            is_valid_prover_message(tx, multisig_address, prover_message, memos)
        }
        XRPLMessage::UserMessage(user_message) => {
            is_valid_user_message(tx, multisig_address, user_message, memos)
        }
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
    memos: HashMap<String, String>,
) -> bool {
    tx.common().account == multisig_address.to_string()
        && memos.get("unsigned_tx_hash")
            == Some(&message.unsigned_tx_hash.to_string().to_uppercase())
}

pub fn is_valid_user_message(
    tx: &Transaction,
    multisig_address: &XRPLAccountId,
    message: &XRPLUserMessage,
    memos: HashMap<String, String>,
) -> bool {
    if let Payment(payment_tx) = &tx {
        let tx_amount = payment_tx.amount.clone();
        match tx.common().meta.clone() {
            Some(tx_meta) => {
                // Context:
                // https://xrpl.org/docs/concepts/payment-types/partial-payments#partial-payments-exploit
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
    false
}

pub fn is_successful_tx(tx: &Transaction) -> bool {
    if let Some(meta) = &tx.common().meta {
        return meta.transaction_result.category() == ResultCategory::Tes;
    }
    false
}

pub fn verify_amount(amount: Amount, message: &XRPLUserMessage) -> bool {
    || -> Option<bool> {
        let amount = match amount {
            Amount::Issued(a) => XRPLPaymentAmount::Issued(
                XRPLToken {
                    issuer: a.issuer.try_into().ok()?,
                    currency: a.currency.try_into().ok()?,
                },
                a.value.try_into().ok()?,
            ),
            Amount::Drops(a) => XRPLPaymentAmount::Drops(a.parse().ok()?),
        };

        Some(amount == message.amount)
    }()
    .unwrap_or(false)
}

pub fn verify_gas_fee_amount(message: &XRPLUserMessage, memos: HashMap<String, String>) -> bool {
    || -> Option<bool> {
        let gas_fee_amount_str: String = match memos.get("gas_fee_amount") {
            None => return Some(false),
            Some(amount) => match hex::decode(amount) {
                Ok(decoded) => match String::from_utf8(decoded) {
                    Ok(s) => s,
                    Err(_) => return Some(false),
                },
                Err(_) => return Some(false),
            },
        };

        let gas_fee_amount = match message.amount.clone() {
            XRPLPaymentAmount::Issued(token, _) => XRPLPaymentAmount::Issued(
                XRPLToken {
                    issuer: token.issuer.try_into().ok()?,
                    currency: token.currency.try_into().ok()?,
                },
                gas_fee_amount_str.try_into().ok()?,
            ),
            XRPLPaymentAmount::Drops(_) => {
                XRPLPaymentAmount::Drops(gas_fee_amount_str.parse().ok()?)
            }
        };

        Some(gas_fee_amount == message.gas_fee_amount && gas_fee_amount <= message.amount)
    }()
    .unwrap_or(false)
}

pub fn verify_memos(memos: HashMap<String, String>, message: &XRPLUserMessage) -> bool {
    let expected_destination_address = hex::encode(message.destination_address.to_string());
    let expected_destination_chain = hex::encode(message.destination_chain.to_string());

    let is_valid_payload_hash = match &message.payload_hash {
        Some(expected_hash) => memos
            .get("payload")
            .map(|memo_payload| {
                hex::decode(memo_payload)
                    .map(|decoded| Keccak256::digest(decoded).to_vec() == *expected_hash)
                    .unwrap_or(false)
            })
            .unwrap_or(false),
        None => !memos.contains_key("payload"),
    };

    memos.get("destination_address").map(|s| s.to_lowercase()) == Some(expected_destination_address)
        && memos.get("destination_chain").map(|s| s.to_lowercase())
            == Some(expected_destination_chain)
        && is_valid_payload_hash
        && verify_gas_fee_amount(message, memos.clone())
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use axelar_wasm_std::msg_id::HexTxHash;
    use axelar_wasm_std::nonempty;
    use router_api::ChainName;
    use xrpl_http_client::Memo;
    use xrpl_types::msg::XRPLUserMessage;
    use xrpl_types::types::{XRPLAccountId, XRPLPaymentAmount};

    use crate::xrpl::verifier::{parse_memos, verify_memos};

    #[test]
    fn test_verify_memos() {
        let memos = vec![
            Memo {
                memo_type: Some("64657374696E6174696F6E5F61646472657373".to_string()), // destination_address
                memo_data: Some("35393236333963313032323363346563366330666663363730653934643238396132356464316164".to_string()), // 592639c10223c4ec6c0ffc670e94d289a25dd1ad
                memo_format: None,
            },
            Memo {
                memo_type: Some("64657374696E6174696F6E5F636861696E".to_string()), // destination_chain
                memo_data: Some("657468657265756D".to_string()),
                memo_format: None,
            },
            Memo {
                memo_type: Some("7061796c6f6164".to_string()), // payload
                memo_data: Some("0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000e474d5020776f726b7320746f6f3f000000000000000000000000000000000000".to_string()),
                memo_format: None,
            },
            Memo {
                memo_type: Some("6761735F6665655F616D6F756E74".to_string()), // gas_fee_amount
                memo_data: Some("3530303030".to_string()), // 50000
                memo_format: None,
            },
        ];
        let mut user_message = XRPLUserMessage {
            tx_id: HexTxHash::new([0; 32]),
            source_address: XRPLAccountId::from_str("raNVNWvhUQzFkDDTdEw3roXRJfMJFVJuQo").unwrap(),
            destination_address: nonempty::String::try_from(
                "592639c10223c4ec6c0ffc670e94d289a25dd1ad".to_string(),
            )
            .unwrap(),
            destination_chain: ChainName::from_str("ethereum").unwrap(),
            payload_hash: Some(
                hex::decode("40e7ed31929500a6a4945765612bac44a71fe18ef7a1bf3d904811558b41354f")
                    .unwrap()
                    .to_vec()
                    .try_into()
                    .unwrap(),
            ),
            amount: XRPLPaymentAmount::Drops(100000),
            gas_fee_amount: XRPLPaymentAmount::Drops(50000),
        };
        assert!(verify_memos(parse_memos(memos.clone()), &user_message));

        user_message.payload_hash = None;
        assert!(!verify_memos(parse_memos(memos.clone()), &user_message));
    }

    #[test]
    fn test_verify_memos_no_payload() {
        let memos = vec![
            Memo {
                memo_type: Some("64657374696E6174696F6E5F61646472657373".to_string()), // destination_address
                memo_data: Some("35393236333963313032323363346563366330666663363730653934643238396132356464316164".to_string()), // 592639c10223c4ec6c0ffc670e94d289a25dd1ad
                memo_format: None,
            },
            Memo {
                memo_type: Some("64657374696E6174696F6E5F636861696E".to_string()), // destination_chain
                memo_data: Some("657468657265756D".to_string()),
                memo_format: None,
            },
            Memo {
                memo_type: Some("6761735F6665655F616D6F756E74".to_string()), // gas_fee_amount
                memo_data: Some("3530303030".to_string()), // 50000
                memo_format: None,
            },
        ];
        let mut user_message = XRPLUserMessage {
            tx_id: HexTxHash::new([0; 32]),
            source_address: XRPLAccountId::from_str("raNVNWvhUQzFkDDTdEw3roXRJfMJFVJuQo").unwrap(),
            destination_address: nonempty::String::try_from(
                "592639c10223c4ec6c0ffc670e94d289a25dd1ad".to_string(),
            )
            .unwrap(),
            destination_chain: ChainName::from_str("ethereum").unwrap(),
            payload_hash: None,
            amount: XRPLPaymentAmount::Drops(100000),
            gas_fee_amount: XRPLPaymentAmount::Drops(50000),
        };
        assert!(verify_memos(parse_memos(memos.clone()), &user_message));

        user_message.payload_hash = Some(
            hex::decode("8a7adf72777a40d790e327be8af2fdb35c2c557f3555c587aae9bc155a9020a8")
                .unwrap()
                .to_vec()
                .try_into()
                .unwrap(),
        );
        assert!(!verify_memos(parse_memos(memos.clone()), &user_message));
    }
}
