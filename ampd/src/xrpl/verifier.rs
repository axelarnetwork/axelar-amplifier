use std::collections::HashMap;

use axelar_wasm_std::voting::Vote;
use sha3::{Digest, Keccak256};
use xrpl_http_client::Transaction::Payment;
use xrpl_http_client::{Amount, Memo, PaymentTransaction, ResultCategory, Transaction};
use xrpl_types::msg::{
    XRPLAddGasMessage, XRPLAddReservesMessage, XRPLMessage, XRPLProverMessage, XRPLUserMessage,
};
use xrpl_types::types::{XRPLAccountId, XRPLPaymentAmount, XRPLToken};

fn parse_memos(memos: &Vec<Memo>) -> HashMap<String, String> {
    memos
        .iter()
        .filter_map(|m| {
            let memo_type = m
                .memo_type
                .as_ref()
                .and_then(|t| hex::decode(t).ok())
                .and_then(|bytes| String::from_utf8(bytes).ok());

            let memo_data = m.memo_data.clone();
            memo_type.zip(memo_data)
        })
        .collect::<HashMap<String, String>>()
}

pub fn verify_message(
    multisig_address: &XRPLAccountId,
    tx: &Transaction,
    message: &XRPLMessage,
) -> Vote {
    let memos = &parse_memos(tx.common().memos.as_ref().unwrap_or(&vec![]));
    let is_valid_message = match message {
        XRPLMessage::ProverMessage(prover_message) => {
            is_valid_prover_message(tx, multisig_address, prover_message, memos)
        }
        XRPLMessage::UserMessage(user_message) => {
            is_valid_user_message(tx, multisig_address, user_message, memos)
        }
        XRPLMessage::AddGasMessage(add_gas_message) => {
            is_valid_add_gas_message(tx, multisig_address, add_gas_message, memos)
        }
        XRPLMessage::AddReservesMessage(add_reserves_message) => {
            is_valid_add_reserves_message(tx, multisig_address, add_reserves_message, memos)
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

fn verify_memo(memos: &HashMap<String, String>, key: &str, expected_value: String) -> bool {
    memos.get(key).map(|s| s.to_lowercase()) == Some(hex::encode(expected_value))
}

pub fn is_valid_prover_message(
    tx: &Transaction,
    multisig_address: &XRPLAccountId,
    message: &XRPLProverMessage,
    memos: &HashMap<String, String>,
) -> bool {
    tx.common().account == multisig_address.to_string()
        && verify_memo(memos, "type", "proof".to_string())
        && verify_memo(
            memos,
            "unsigned_tx_hash",
            message.unsigned_tx_hash.to_string(),
        )
}

fn verify_payment_flags(payment_tx: &PaymentTransaction) -> bool {
    payment_tx.flags.is_empty() // TODO: whitelist specific flags
}

pub fn is_valid_user_message(
    tx: &Transaction,
    multisig_address: &XRPLAccountId,
    message: &XRPLUserMessage,
    memos: &HashMap<String, String>,
) -> bool {
    if let Payment(payment_tx) = &tx {
        payment_tx.destination == multisig_address.to_string()
            && message.source_address.to_string() == tx.common().account
            && verify_delivered_full_amount(tx, payment_tx.amount.clone())
            && verify_amount(message.amount.clone(), payment_tx.amount.clone())
            && verify_user_memos(memos, message)
            && verify_payment_flags(payment_tx)
    } else {
        false
    }
}

fn verify_user_memos(memos: &HashMap<String, String>, message: &XRPLUserMessage) -> bool {
    verify_memo(memos, "type", "interchain_transfer".to_string())
        && verify_memo(
            memos,
            "destination_chain",
            message.destination_chain.to_string(),
        )
        && verify_memo(
            memos,
            "destination_address",
            message.destination_address.to_string(),
        )
        && verify_payload_hash(memos, message)
        && verify_gas_fee_amount(message, memos)
}

fn is_valid_add_gas_message(
    tx: &Transaction,
    multisig_address: &XRPLAccountId,
    message: &XRPLAddGasMessage,
    memos: &HashMap<String, String>,
) -> bool {
    if let Payment(payment_tx) = &tx {
        payment_tx.destination == multisig_address.to_string()
            && verify_delivered_full_amount(tx, payment_tx.amount.clone())
            && verify_amount(message.amount.clone(), payment_tx.amount.clone())
            && verify_memo(memos, "type", "add_gas".to_string())
            && verify_memo(memos, "tx_id", message.msg_tx_id.to_string())
            && verify_payment_flags(payment_tx)
    } else {
        false
    }
}

fn is_valid_add_reserves_message(
    tx: &Transaction,
    multisig_address: &XRPLAccountId,
    message: &XRPLAddReservesMessage,
    memos: &HashMap<String, String>,
) -> bool {
    if let Payment(payment_tx) = &tx {
        if let Amount::Drops(amount) = payment_tx.amount.clone() {
            return payment_tx.destination == multisig_address.to_string()
                && verify_delivered_full_amount(tx, payment_tx.amount.clone())
                && amount == message.amount.to_string()
                && verify_memo(memos, "type", "add_fee_reserve".to_string())
                && verify_payment_flags(payment_tx);
        }
    }
    false
}

pub fn is_successful_tx(tx: &Transaction) -> bool {
    if let Some(meta) = &tx.common().meta {
        return meta.transaction_result.category() == ResultCategory::Tes;
    }
    false
}

// Context:
// https://xrpl.org/docs/concepts/payment-types/partial-payments#partial-payments-exploit
fn verify_delivered_full_amount(tx: &Transaction, expected_amount: Amount) -> bool {
    if let Some(meta) = &tx.common().meta {
        return meta.delivered_amount == Some(expected_amount);
    }
    false
}

pub fn verify_amount(expected_amount: XRPLPaymentAmount, actual_amount: Amount) -> bool {
    || -> Option<bool> {
        let amount = match actual_amount {
            Amount::Issued(a) => XRPLPaymentAmount::Issued(
                XRPLToken {
                    issuer: a.issuer.try_into().ok()?,
                    currency: a.currency.try_into().ok()?,
                },
                a.value.try_into().ok()?,
            ),
            Amount::Drops(a) => XRPLPaymentAmount::Drops(a.parse().ok()?),
        };

        Some(amount == expected_amount)
    }()
    .unwrap_or(false)
}

pub fn verify_gas_fee_amount(message: &XRPLUserMessage, memos: &HashMap<String, String>) -> bool {
    || -> Option<bool> {
        let gas_fee_amount_str = match memos
            .get("gas_fee_amount")
            .and_then(|amount| hex::decode(amount).ok())
            .and_then(|decoded| String::from_utf8(decoded).ok())
        {
            Some(gas_fee_amount_str) => gas_fee_amount_str,
            None => return None,
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

pub fn verify_payload_hash(memos: &HashMap<String, String>, message: &XRPLUserMessage) -> bool {
    match &message.payload_hash {
        Some(expected_hash) => memos
            .get("payload")
            .map(|memo_payload| {
                hex::decode(memo_payload)
                    .map(|decoded| Keccak256::digest(decoded).to_vec() == *expected_hash)
                    .unwrap_or(false)
            })
            .unwrap_or(false),
        None => !memos.contains_key("payload"),
    }
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

    use crate::xrpl::verifier::{parse_memos, verify_user_memos};

    #[test]
    fn test_verify_user_memos() {
        let memos = vec![
            Memo {
                memo_type: Some("74797065".to_string()), // type
                memo_data: Some("696E746572636861696E5F7472616E73666572".to_string()), // interchain_transfer
                memo_format: None,
            },
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
        assert!(verify_user_memos(&parse_memos(&memos), &user_message));

        user_message.payload_hash = None;
        assert!(!verify_user_memos(&parse_memos(&memos), &user_message));
    }

    #[test]
    fn test_verify_user_memos_no_payload() {
        let memos = vec![
            Memo {
                memo_type: Some("74797065".to_string()), // type
                memo_data: Some("696E746572636861696E5F7472616E73666572".to_string()), // interchain_transfer
                memo_format: None,
            },
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
        assert!(verify_user_memos(&parse_memos(&memos), &user_message));

        user_message.payload_hash = Some(
            hex::decode("8a7adf72777a40d790e327be8af2fdb35c2c557f3555c587aae9bc155a9020a8")
                .unwrap()
                .to_vec()
                .try_into()
                .unwrap(),
        );
        assert!(!verify_user_memos(&parse_memos(&memos), &user_message));
    }
}
