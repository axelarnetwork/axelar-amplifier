use std::collections::HashMap;
use std::ops::Sub;

use axelar_wasm_std::voting::Vote;
use sha3::{Digest, Keccak256};
use xrpl_http_client::Transaction::Payment;
use xrpl_http_client::{Amount, Memo, PaymentTransaction, ResultCategory, Transaction};
use xrpl_types::msg::{
    XRPLAddGasMessage, XRPLAddReservesMessage, XRPLCallContractMessage,
    XRPLInterchainTransferMessage, XRPLMessage, XRPLMessageType, XRPLProverMessage,
};
use xrpl_types::types::{XRPLAccountId, XRPLPaymentAmount, XRPLToken};

fn parse_memos(memos: &[Memo]) -> HashMap<String, String> {
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

fn verify_equal_amount(expected_amount: XRPLPaymentAmount, actual_amount: Amount) -> bool {
    verify_amount(expected_amount, actual_amount, |a, b| a == b)
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
        XRPLMessage::InterchainTransferMessage(interchain_transfer_message) => {
            is_valid_interchain_transfer_message(
                tx,
                multisig_address,
                interchain_transfer_message,
                memos,
            )
        }
        XRPLMessage::CallContractMessage(call_contract_message) => {
            is_valid_call_contract_message(tx, multisig_address, call_contract_message, memos)
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
fn is_validated_tx(tx: &Transaction) -> bool {
    matches!(tx.common().validated, Some(true))
}

fn verify_memo(memos: &HashMap<String, String>, key: &str, expected_value: String) -> bool {
    memos.get(key).map(|s| s.to_lowercase()) == Some(hex::encode(expected_value))
}

fn is_valid_prover_message(
    tx: &Transaction,
    multisig_address: &XRPLAccountId,
    message: &XRPLProverMessage,
    memos: &HashMap<String, String>,
) -> bool {
    tx.common().account == multisig_address.to_string()
        && verify_memo(memos, "type", XRPLMessageType::Proof.to_string())
        && verify_memo(
            memos,
            "unsigned_tx_hash",
            message
                .unsigned_tx_hash
                .tx_hash_as_hex_no_prefix()
                .to_string(),
        )
}

fn verify_payment_flags(payment_tx: &PaymentTransaction) -> bool {
    payment_tx.flags.is_empty() // TODO: whitelist specific flags
}

fn is_valid_interchain_transfer_message(
    tx: &Transaction,
    multisig_address: &XRPLAccountId,
    message: &XRPLInterchainTransferMessage,
    memos: &HashMap<String, String>,
) -> bool {
    if let Payment(payment_tx) = &tx {
        // Mirror the relayer (transfer = payment - gas); subtracting avoids the IOU precision loss of re-adding.
        let payment_amount = match to_xrpl_payment_amount(payment_tx.amount.clone()) {
            Some(amount) => amount,
            None => return false,
        };
        let expected_transfer_amount = match payment_amount.sub(message.gas_fee_amount.clone()) {
            Ok(amount) => amount,
            Err(_) => return false, // gas > payment, or token mismatch
        };

        payment_tx.destination == multisig_address.to_string()
            && message.source_address.to_string() == tx.common().account
            && verify_delivered_full_amount(tx, payment_tx.amount.clone())
            && message.transfer_amount == expected_transfer_amount
            && verify_interchain_transfer_memos(memos, message)
            && verify_payment_flags(payment_tx)
    } else {
        false
    }
}

fn is_valid_call_contract_message(
    tx: &Transaction,
    multisig_address: &XRPLAccountId,
    message: &XRPLCallContractMessage,
    memos: &HashMap<String, String>,
) -> bool {
    if let Payment(payment_tx) = &tx {
        payment_tx.destination == multisig_address.to_string()
            && message.source_address.to_string() == tx.common().account
            && verify_delivered_full_amount(tx, payment_tx.amount.clone())
            && verify_equal_amount(message.gas_fee_amount.clone(), payment_tx.amount.clone())
            && verify_call_contract_memos(memos, message)
            && verify_payment_flags(payment_tx)
    } else {
        false
    }
}

fn verify_interchain_transfer_memos(
    memos: &HashMap<String, String>,
    message: &XRPLInterchainTransferMessage,
) -> bool {
    verify_memo(
        memos,
        "type",
        XRPLMessageType::InterchainTransfer.to_string(),
    ) && verify_memo(
        memos,
        "destination_chain",
        message.destination_chain.to_string(),
    ) && verify_memo(
        memos,
        "destination_address",
        message.destination_address.to_string(),
    ) && verify_payload_hash(memos, message)
        && verify_gas_fee_amount(memos, message)
}

fn verify_call_contract_memos(
    memos: &HashMap<String, String>,
    message: &XRPLCallContractMessage,
) -> bool {
    verify_memo(memos, "type", XRPLMessageType::CallContract.to_string())
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
        && verify_payload(memos, message.payload_hash)
}

fn is_valid_add_gas_message(
    tx: &Transaction,
    multisig_address: &XRPLAccountId,
    message: &XRPLAddGasMessage,
    memos: &HashMap<String, String>,
) -> bool {
    if let Payment(payment_tx) = &tx {
        payment_tx.destination == multisig_address.to_string()
            && message.source_address.to_string() == tx.common().account
            && verify_delivered_full_amount(tx, payment_tx.amount.clone())
            && verify_equal_amount(message.amount.clone(), payment_tx.amount.clone())
            && verify_memo(memos, "type", XRPLMessageType::AddGas.to_string())
            && verify_memo(
                memos,
                "msg_id",
                message.msg_id.tx_hash_as_hex_no_prefix().to_string(),
            )
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
        return payment_tx.destination == multisig_address.to_string()
            && verify_delivered_full_amount(tx, payment_tx.amount.clone())
            && verify_equal_amount(
                XRPLPaymentAmount::Drops(message.amount),
                payment_tx.amount.clone(),
            )
            && verify_memo(memos, "type", XRPLMessageType::AddReserves.to_string())
            && verify_payment_flags(payment_tx);
    }
    false
}

fn is_successful_tx(tx: &Transaction) -> bool {
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

fn to_xrpl_payment_amount(actual_amount: Amount) -> Option<XRPLPaymentAmount> {
    match actual_amount {
        Amount::Issued(a) => Some(XRPLPaymentAmount::Issued(
            XRPLToken {
                issuer: a.issuer.try_into().ok()?,
                currency: a.currency.try_into().ok()?,
            },
            a.value.try_into().ok()?,
        )),
        Amount::Drops(a) => Some(XRPLPaymentAmount::Drops(a.parse().ok()?)),
    }
}

fn verify_amount(
    expected_amount: XRPLPaymentAmount,
    actual_amount: Amount,
    cmp: impl Fn(XRPLPaymentAmount, XRPLPaymentAmount) -> bool,
) -> bool {
    to_xrpl_payment_amount(actual_amount)
        .map(|amount| cmp(expected_amount, amount))
        .unwrap_or(false)
}

fn verify_gas_fee_amount(
    memos: &HashMap<String, String>,
    message: &XRPLInterchainTransferMessage,
) -> bool {
    || -> Option<bool> {
        let gas_fee_amount_str = memos
            .get("gas_fee_amount")
            .and_then(|amount| hex::decode(amount).ok())
            .and_then(|decoded| String::from_utf8(decoded).ok())?;

        let gas_fee_amount = match message.transfer_amount.clone() {
            XRPLPaymentAmount::Issued(token, _) => XRPLPaymentAmount::Issued(
                XRPLToken {
                    issuer: token.issuer,
                    currency: token.currency,
                },
                gas_fee_amount_str.try_into().ok()?,
            ),
            XRPLPaymentAmount::Drops(_) => {
                XRPLPaymentAmount::Drops(gas_fee_amount_str.parse().ok()?)
            }
        };

        Some(gas_fee_amount == message.gas_fee_amount)
    }()
    .unwrap_or(false)
}

fn verify_payload(memos: &HashMap<String, String>, expected_payload_hash: [u8; 32]) -> bool {
    memos
        .get("payload")
        .map(|memo_payload| {
            hex::decode(memo_payload)
                .map(|decoded| Keccak256::digest(decoded).to_vec() == expected_payload_hash)
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

fn verify_payload_hash(
    memos: &HashMap<String, String>,
    message: &XRPLInterchainTransferMessage,
) -> bool {
    match &message.payload_hash {
        Some(expected_hash) => verify_payload(memos, *expected_hash),
        None => !memos.contains_key("payload"),
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use axelar_wasm_std::msg_id::HexTxHash;
    use axelar_wasm_std::voting::Vote;
    use axelar_wasm_std::{chain_name_raw, nonempty};
    use xrpl_http_client::{
        Amount, IssuedAmount, Memo, Meta, PaymentTransaction, Transaction, TransactionCommon,
        TransactionResult,
    };
    use xrpl_types::msg::{XRPLInterchainTransferMessage, XRPLMessage};
    use xrpl_types::types::{
        XRPLAccountId, XRPLCurrency, XRPLPaymentAmount, XRPLToken, XRPLTokenAmount,
    };

    use crate::xrpl::verifier::{parse_memos, verify_interchain_transfer_memos, verify_message};

    #[test]
    fn test_verify_interchain_transfer_memos() {
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
                memo_data: Some("457468657265756D".to_string()),
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
        let mut interchain_transfer_message = XRPLInterchainTransferMessage {
            tx_id: HexTxHash::new([0; 32]),
            source_address: XRPLAccountId::from_str("raNVNWvhUQzFkDDTdEw3roXRJfMJFVJuQo").unwrap(),
            destination_address: nonempty::String::try_from(
                "592639c10223c4ec6c0ffc670e94d289a25dd1ad".to_string(),
            )
            .unwrap(),
            destination_chain: chain_name_raw!("Ethereum"),
            payload_hash: Some(
                hex::decode("40e7ed31929500a6a4945765612bac44a71fe18ef7a1bf3d904811558b41354f")
                    .unwrap()
                    .to_vec()
                    .try_into()
                    .unwrap(),
            ),
            transfer_amount: XRPLPaymentAmount::Drops(100000),
            gas_fee_amount: XRPLPaymentAmount::Drops(50000),
        };
        assert!(verify_interchain_transfer_memos(
            &parse_memos(&memos),
            &interchain_transfer_message
        ));

        interchain_transfer_message.payload_hash = None;
        assert!(!verify_interchain_transfer_memos(
            &parse_memos(&memos),
            &interchain_transfer_message
        ));
    }

    #[test]
    fn test_verify_interchain_transfer_memos_no_payload() {
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
        let mut interchain_transfer_message = XRPLInterchainTransferMessage {
            tx_id: HexTxHash::new([0; 32]),
            source_address: XRPLAccountId::from_str("raNVNWvhUQzFkDDTdEw3roXRJfMJFVJuQo").unwrap(),
            destination_address: nonempty::String::try_from(
                "592639c10223c4ec6c0ffc670e94d289a25dd1ad".to_string(),
            )
            .unwrap(),
            destination_chain: chain_name_raw!("ethereum"),
            payload_hash: None,
            transfer_amount: XRPLPaymentAmount::Drops(100000),
            gas_fee_amount: XRPLPaymentAmount::Drops(50000),
        };
        assert!(verify_interchain_transfer_memos(
            &parse_memos(&memos),
            &interchain_transfer_message
        ));

        interchain_transfer_message.payload_hash = Some(
            hex::decode("8a7adf72777a40d790e327be8af2fdb35c2c557f3555c587aae9bc155a9020a8")
                .unwrap()
                .to_vec()
                .try_into()
                .unwrap(),
        );
        assert!(!verify_interchain_transfer_memos(
            &parse_memos(&memos),
            &interchain_transfer_message
        ));
    }

    // --- Integration-style tests for the interchain-transfer amount check ------
    //
    // These build a full XRPL `Payment` (the trusted on-chain transaction) and a
    // claimed `XRPLInterchainTransferMessage` (the Cosmos-side poll event), then
    // drive `verify_message`. They simulate an honest relayer (which sets
    // transfer_amount = payment - gas) and malicious ones (under-reporting the
    // transfer, or claiming a gas fee that doesn't match the on-chain memo).

    const ISSUER: &str = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";
    const SOURCE: &str = "raNVNWvhUQzFkDDTdEw3roXRJfMJFVJuQo";
    const MULTISIG: &str = "rfmS3zqrQrka8wVyhXifEeyTwe8AMz2Yhw";
    const DESTINATION_ADDRESS: &str = "592639c10223c4ec6c0ffc670e94d289a25dd1ad";

    fn multisig() -> XRPLAccountId {
        XRPLAccountId::from_str(MULTISIG).unwrap()
    }

    fn usd_token() -> XRPLToken {
        XRPLToken {
            issuer: XRPLAccountId::from_str(ISSUER).unwrap(),
            currency: XRPLCurrency::new("USD").unwrap(),
        }
    }

    fn issued(value: &str) -> XRPLPaymentAmount {
        XRPLPaymentAmount::Issued(usd_token(), XRPLTokenAmount::from_str(value).unwrap())
    }

    fn issued_onchain(value: &str) -> Amount {
        Amount::Issued(IssuedAmount {
            value: value.to_string(),
            currency: "USD".to_string(),
            issuer: ISSUER.to_string(),
        })
    }

    fn memo(key: &str, value: &str) -> Memo {
        Memo {
            memo_type: Some(hex::encode(key)),
            memo_data: Some(hex::encode(value)),
            memo_format: None,
        }
    }

    fn interchain_transfer_memos(gas_value: &str) -> Vec<Memo> {
        vec![
            memo("type", "interchain_transfer"),
            memo("destination_address", DESTINATION_ADDRESS),
            memo("destination_chain", "Ethereum"),
            memo("gas_fee_amount", gas_value),
        ]
    }

    // `delivered` defaults to `amount` (full delivery).
    fn payment_tx(amount: Amount, delivered: Option<Amount>, memos: Vec<Memo>) -> Transaction {
        let delivered_amount = Some(delivered.unwrap_or_else(|| amount.clone()));
        Transaction::Payment(PaymentTransaction {
            common: TransactionCommon {
                account: SOURCE.to_string(),
                memos: Some(memos),
                validated: Some(true),
                meta: Some(Meta {
                    affected_nodes: vec![],
                    transaction_index: 0,
                    transaction_result: TransactionResult::tesSUCCESS,
                    delivered_amount,
                }),
                ..Default::default()
            },
            flags: Default::default(),
            amount,
            destination: MULTISIG.to_string(),
            destination_tag: None,
            invoice_id: None,
            send_max: None,
            deliver_min: None,
        })
    }

    fn transfer_message(
        transfer_amount: XRPLPaymentAmount,
        gas_fee_amount: XRPLPaymentAmount,
    ) -> XRPLMessage {
        XRPLMessage::InterchainTransferMessage(XRPLInterchainTransferMessage {
            tx_id: HexTxHash::new([0; 32]),
            source_address: XRPLAccountId::from_str(SOURCE).unwrap(),
            destination_address: nonempty::String::try_from(DESTINATION_ADDRESS.to_string())
                .unwrap(),
            destination_chain: chain_name_raw!("Ethereum"),
            payload_hash: None,
            transfer_amount,
            gas_fee_amount,
        })
    }

    #[test]
    fn honest_drops_transfer_is_accepted() {
        // payment 100_000 drops, gas 50_000 => transfer 50_000
        let tx = payment_tx(
            Amount::Drops("100000".to_string()),
            None,
            interchain_transfer_memos("50000"),
        );
        let message = transfer_message(
            XRPLPaymentAmount::Drops(50_000),
            XRPLPaymentAmount::Drops(50_000),
        );
        assert_eq!(
            verify_message(&multisig(), &tx, &message),
            Vote::SucceededOnChain
        );
    }

    #[test]
    fn malicious_relayer_underreporting_drops_transfer_is_rejected() {
        // underreport attack: claims transfer 1; expected = 100_000 - 50_000 = 50_000.
        let tx = payment_tx(
            Amount::Drops("100000".to_string()),
            None,
            interchain_transfer_memos("50000"),
        );
        let message = transfer_message(
            XRPLPaymentAmount::Drops(1),
            XRPLPaymentAmount::Drops(50_000),
        );
        assert_eq!(verify_message(&multisig(), &tx, &message), Vote::NotFound);
    }

    #[test]
    fn claimed_gas_not_matching_memo_is_rejected() {
        // transfer+gas is self-consistent (60k+40k=100k), but claimed gas 40k != memo 50k.
        let tx = payment_tx(
            Amount::Drops("100000".to_string()),
            None,
            interchain_transfer_memos("50000"),
        );
        let message = transfer_message(
            XRPLPaymentAmount::Drops(60_000),
            XRPLPaymentAmount::Drops(40_000),
        );
        assert_eq!(verify_message(&multisig(), &tx, &message), Vote::NotFound);
    }

    #[test]
    fn gas_exceeding_payment_is_rejected() {
        // gas 200_000 > payment 100_000 => sub underflows.
        let tx = payment_tx(
            Amount::Drops("100000".to_string()),
            None,
            interchain_transfer_memos("200000"),
        );
        let message = transfer_message(
            XRPLPaymentAmount::Drops(1),
            XRPLPaymentAmount::Drops(200_000),
        );
        assert_eq!(verify_message(&multisig(), &tx, &message), Vote::NotFound);
    }

    #[test]
    fn partial_payment_is_rejected() {
        // Amount says 100_000 but only 1 drop delivered.
        let tx = payment_tx(
            Amount::Drops("100000".to_string()),
            Some(Amount::Drops("1".to_string())),
            interchain_transfer_memos("50000"),
        );
        let message = transfer_message(
            XRPLPaymentAmount::Drops(50_000),
            XRPLPaymentAmount::Drops(50_000),
        );
        assert_eq!(verify_message(&multisig(), &tx, &message), Vote::NotFound);
    }

    #[test]
    fn honest_issued_transfer_with_sub_ulp_gas_is_accepted() {
        // IOU precision: transfer = payment(…456) - gas(1e-10) = …455. `transfer+gas==payment`
        // would wrongly reject this; `payment-gas` accepts it.
        let tx = payment_tx(
            issued_onchain("1234567.890123456"),
            None,
            interchain_transfer_memos("0.0000000001"),
        );
        let message = transfer_message(issued("1234567.890123455"), issued("0.0000000001"));
        assert_eq!(
            verify_message(&multisig(), &tx, &message),
            Vote::SucceededOnChain
        );
    }

    #[test]
    fn malicious_relayer_underreporting_issued_transfer_is_rejected() {
        let tx = payment_tx(
            issued_onchain("1234567.890123456"),
            None,
            interchain_transfer_memos("0.0000000001"),
        );
        let message = transfer_message(issued("1"), issued("0.0000000001"));
        assert_eq!(verify_message(&multisig(), &tx, &message), Vote::NotFound);
    }
}
