use std::collections::HashMap;

use axelar_wasm_std::voting::Vote;
use base64::Engine as _;
use borsh::{BorshDeserialize, BorshSerialize};

use auth_weighted::types::operator::Operators;
use base64::{self, engine::general_purpose};
use thiserror::Error;
use tracing::info;

use crate::handlers::solana_verify_worker_set::{self, WorkerSetConfirmation};

use super::{
    json_rpc::{AccountInfo, EncodedConfirmedTransactionWithStatusMeta},
    pub_key_wrapper::PubkeyWrapper,
};

// Gateway program logs.
// Logged when the Gateway receives an outbound message.
#[derive(Debug, PartialEq, BorshDeserialize, BorshSerialize, Clone)]
#[repr(u8)]
pub enum GatewayEvent {
    OperatorshipTransferred {
        /// Pubkey of the account that stores the key rotation information.
        info_account_address: PubkeyWrapper,
    },
}

impl GatewayEvent {
    // Try to parse a [`CallContractEvent`] out of a Solana program log line.
    fn parse_log(log: &String) -> Option<Self> {
        let cleaned_input = log
            .trim()
            .trim_start_matches("Program data:")
            .split_whitespace()
            .flat_map(decode_base64)
            .next()?;
        borsh::from_slice(&cleaned_input).ok()
    }
}

#[inline]
fn decode_base64(input: &str) -> Option<Vec<u8>> {
    general_purpose::STANDARD.decode(input).ok()
}

#[derive(Error, Debug, PartialEq)]
pub enum VerificationError {
    #[error("Failed to parse tx log messages")]
    NoLogMessages,
    #[error("Tried to get gateway event from program logs, but couldn't find anything.")]
    NoGatewayEventFound,
    #[error("Parsing error: {0}")]
    ParsingError(String),
}

type Result<T> = std::result::Result<T, VerificationError>;

pub fn parse_gateway_event(tx: &EncodedConfirmedTransactionWithStatusMeta) -> Result<GatewayEvent> {
    if let None = tx.meta.log_messages {
        return Err(VerificationError::NoLogMessages);
    }
    let program_data = tx.meta.log_messages.as_ref().unwrap();
    program_data
        .into_iter()
        .find_map(|program_log| GatewayEvent::parse_log(program_log))
        .ok_or(VerificationError::NoGatewayEventFound)
}

pub async fn verify_worker_set(
    source_gateway_address: &String,
    sol_tx: &EncodedConfirmedTransactionWithStatusMeta,
    worker_set: &WorkerSetConfirmation,
    account_info: &AccountInfo,
) -> Vote {
    if !sol_tx
        .transaction
        .message
        .account_keys
        .contains(source_gateway_address)
    {
        info!(
            tx_id = &worker_set.tx_id,
            "tx does not contains source_gateway_address"
        );
        return Vote::FailedOnChain;
    }

    if sol_tx.transaction.signatures.is_empty() {
        info!(tx_id = &worker_set.tx_id, "tx do not contain signatures");
        return Vote::FailedOnChain;
    }

    if worker_set.tx_id != sol_tx.transaction.signatures[0] {
        info!(tx_id = &worker_set.tx_id, "tx_id do not match");
        return Vote::FailedOnChain;
    }

    let onchain_operators = match parse_onchain_operators(account_info) {
        Ok(ops) => ops,
        Err(err) => {
            info!(tx_id = &worker_set.tx_id, err = err.to_string());
            return Vote::FailedOnChain;
        }
    };

    match verify_worker_set_operators_data(&worker_set.operators, &onchain_operators) {
        true => Vote::SucceededOnChain,
        false => Vote::FailedOnChain,
    }
}

fn verify_worker_set_operators_data(
    ops: &solana_verify_worker_set::Operators,
    aw_ops: &Operators,
) -> bool {
    ops == aw_ops
}

fn parse_onchain_operators(account_info: &AccountInfo) -> Result<Operators> {
    if account_info.value.data.len() < 2 {
        return Err(VerificationError::ParsingError(
            "Could not find solana account data.".to_string(),
        ));
    }

    let account_data = match decode_base64(&account_info.value.data[0]) {
        Some(data) => data,
        None => {
            return Err(VerificationError::ParsingError(
                "Cannot base64 decode account data.".to_string(),
            ))
        }
    };

    let operators = match borsh::de::from_slice::<Operators>(&account_data) {
        Ok(ops) => ops,
        Err(err) => {
            return Err(VerificationError::ParsingError(format!(
                "Cannot borsh decode account data: {}",
                err.to_string()
            )))
        }
    };

    Ok(operators)
}

impl PartialEq<auth_weighted::types::operator::Operators> for solana_verify_worker_set::Operators {
    fn eq(&self, aw_ops: &auth_weighted::types::operator::Operators) -> bool {
        if self.threshold != *aw_ops.threshold() {
            return false;
        }

        // Creating a hashmap for querying the data later. Using a not fixed size key like
        // Vec<u8> could not be the best. We expect a 33 bytes slice as address. See ['auth_weighted::types::Address::ECDSA_COMPRESSED_PUBKEY_LEN']
        // So probably we should try to use that after testing the first POC in order to reduce the domain of the key.
        let addresses_weights_res: Result<HashMap<Vec<u8>, crate::types::U256>> = self
            .weights_by_addresses
            .iter()
            // We are assuming here the solana address to come hex encoded. So we decode it.
            .map(|(sol_addr_hex, sol_weight)| {
                let sol_addr = hex::decode(sol_addr_hex).map_err(|e| {
                    VerificationError::ParsingError(format!(
                        "Failed hex-decoding sol address: {}",
                        e.to_string()
                    ))
                })?;
                Ok((sol_addr, sol_weight.clone()))
            })
            .collect();

        let addresses_weights = match addresses_weights_res {
            Ok(addr_weight_map) => addr_weight_map,
            Err(_) => return false, // Todo, omitting some err info here. This could be indicating the
                                    // internal hex parse operation should not be happening here. Maybe we need scale up that logic,
                                    // and preparing conversions beforehand in another type.
        };

        // Iterate both iterators axelar addresses and weights which  at the same time,
        // while querying the previously created map, which contains
        match aw_ops
            .addresses()
            .iter()
            .zip(aw_ops.weights())
            .try_for_each(|(address, weight)| {
                let axelar_addr_weight = addresses_weights.get_key_value(address.as_ref());
                if axelar_addr_weight.is_none() {
                    return Err(());
                }
                let (axelar_address, axelar_weight) = axelar_addr_weight.unwrap();

                if address.as_ref() != axelar_address {
                    return Err(());
                }

                if weight != axelar_weight {
                    return Err(());
                }
                Ok(())
            }) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

impl PartialEq<crate::types::U256> for auth_weighted::types::u256::U256 {
    fn eq(&self, loc_u256: &crate::types::U256) -> bool {
        let mut b: [u8; 32] = [0; 32];
        loc_u256.to_little_endian(&mut b);
        self.to_le_bytes() == b
    }
}

impl PartialEq<auth_weighted::types::u256::U256> for crate::types::U256 {
    fn eq(&self, aw_u256: &auth_weighted::types::u256::U256) -> bool {
        let mut b: [u8; 32] = [0; 32];
        self.to_little_endian(&mut b);
        aw_u256.to_le_bytes() == b
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        handlers::solana_verify_worker_set::Operators, solana::json_rpc::AccountInfoValue,
    };

    use super::*;
    use auth_weighted::types::{address::Address, u256::U256};
    use cosmwasm_std::Uint256;
    use std::convert::TryFrom;

    #[test]
    fn test_correct_deserialization_auth_weight_operators() {
        let onchain_operators = auth_weighted::types::operator::Operators::new(
            vec![
                Address::try_from(
                    "03f57d1a813febaccbe6429603f9ec57969511b76cd680452dba91fa01f54e756d",
                )
                .unwrap(),
                Address::try_from(
                    "03f57d1a813febaccbe6429603f9ec57969511b76cd680452dba91fa01f54e756e",
                )
                .unwrap(),
            ],
            vec![U256::from(100u8), U256::from(200u8)],
            U256::from(1u8),
        );

        let mut op_buff = Vec::new();
        onchain_operators.serialize(&mut op_buff).unwrap();
        let onchain_operators_b64 = general_purpose::STANDARD.encode(op_buff);

        let onchain_account_info = AccountInfo {
            value: AccountInfoValue {
                data: vec![onchain_operators_b64, "base64".to_string()],
            },
        };

        assert_eq!(
            onchain_operators,
            parse_onchain_operators(&onchain_account_info).unwrap()
        )
    }

    #[test]
    fn test_incorrect_deserialization_auth_weight_operators_failing_index() {
        let onchain_account_info = AccountInfo {
            value: AccountInfoValue {
                data: vec![], // No data
            },
        };

        assert_eq!(
            parse_onchain_operators(&onchain_account_info),
            Err(VerificationError::ParsingError(
                "Could not find solana account data.".to_string()
            ))
        )
    }

    #[test]
    fn test_incorrect_deserialization_auth_weight_operators_failing_base64() {
        let onchain_account_info = AccountInfo {
            value: AccountInfoValue {
                data: vec!["22".to_string(), "base64".to_string()], // Bad data base64.
            },
        };

        assert_eq!(
            parse_onchain_operators(&onchain_account_info),
            Err(VerificationError::ParsingError(
                "Cannot base64 decode account data.".to_string()
            ))
        )
    }

    #[test]
    fn test_incorrect_deserialization_auth_weight_operators_failing_borsh_deserialization() {
        let onchain_operators = auth_weighted::types::operator::Operators::new(
            vec![
                Address::try_from(
                    "03f57d1a813febaccbe6429603f9ec57969511b76cd680452dba91fa01f54e756d",
                )
                .unwrap(),
                Address::try_from(
                    "03f57d1a813febaccbe6429603f9ec57969511b76cd680452dba91fa01f54e756e",
                )
                .unwrap(),
            ],
            vec![U256::from(100u8), U256::from(200u8)],
            U256::from(1u8),
        );

        let mut op_buff = Vec::new();
        onchain_operators.serialize(&mut op_buff).unwrap();
        op_buff[0] = 1; // We mangle the data in order to borsh to fail.
        let onchain_operators_b64 = general_purpose::STANDARD.encode(op_buff);

        let onchain_account_info = AccountInfo {
            value: AccountInfoValue {
                data: vec![onchain_operators_b64, "base64".to_string()],
            },
        };

        assert_eq!(
            parse_onchain_operators(&onchain_account_info),
            Err(VerificationError::ParsingError(
                "Cannot borsh decode account data: failed to fill whole buffer".to_string()
            ))
        );
    }

    #[test]
    fn test_verify_worker_set_operators_data_happy_path() {
        let (ops, sol_ops) = matching_axelar_operators_and_onchain_operators();
        assert!(verify_worker_set_operators_data(&ops, &sol_ops))
    }

    #[test]
    fn test_verify_worker_set_operators_data_fails_not_eq_threshold() {
        let (mut ops, sol_ops) = matching_axelar_operators_and_onchain_operators();
        ops.threshold = crate::types::U256::from(Uint256::MAX);
        assert_eq!(false, verify_worker_set_operators_data(&ops, &sol_ops))
    }

    #[test]
    fn test_verify_worker_set_operators_data_fails_not_eq_op_addresses() {
        let (mut ops, sol_ops) = matching_axelar_operators_and_onchain_operators();
        ops.weights_by_addresses = vec![
            (
                "03f57d1a813febaccbe6429603f9ec57969511b76cd680452dba91fa01f54e756d".to_string(),
                crate::types::U256::from(Uint256::from_u128(100)),
            ),
            (
                //"03f57d1a813febaccbe6429603f9ec57969511b76cd680452dba91fa01f54e756e" --> original.
                "03f57d1a813febaccbe6429603f9ec57969511b76cd680452dba91fa01f54e756a" // --> changed last character.
                    .to_string(),
                crate::types::U256::from(Uint256::from_u128(200)),
            ),
        ];
        assert_eq!(false, verify_worker_set_operators_data(&ops, &sol_ops))
    }

    #[test]
    fn test_verify_worker_set_operators_data_fails_not_eq_op_weights() {
        let (mut ops, sol_ops) = matching_axelar_operators_and_onchain_operators();
        ops.weights_by_addresses = vec![
            (
                "03f57d1a813febaccbe6429603f9ec57969511b76cd680452dba91fa01f54e756d".to_string(),
                crate::types::U256::from(Uint256::from_u128(100)),
            ),
            (
                "03f57d1a813febaccbe6429603f9ec57969511b76cd680452dba91fa01f54e756e".to_string(),
                crate::types::U256::from(Uint256::from_u128(1)), // here is a different weight than expected.
            ),
        ];
        assert_eq!(false, verify_worker_set_operators_data(&ops, &sol_ops))
    }

    fn matching_axelar_operators_and_onchain_operators(
    ) -> (Operators, auth_weighted::types::operator::Operators) {
        let onchain_operators = auth_weighted::types::operator::Operators::new(
            vec![
                Address::try_from(
                    "03f57d1a813febaccbe6429603f9ec57969511b76cd680452dba91fa01f54e756d",
                )
                .unwrap(),
                Address::try_from(
                    "03f57d1a813febaccbe6429603f9ec57969511b76cd680452dba91fa01f54e756e",
                )
                .unwrap(),
            ],
            vec![U256::from(100u8), U256::from(200u8)],
            U256::from(1u8),
        );

        let axelar_operators = Operators {
            weights_by_addresses: vec![
                (
                    "03f57d1a813febaccbe6429603f9ec57969511b76cd680452dba91fa01f54e756d"
                        .to_string(),
                    crate::types::U256::from(Uint256::from_u128(100)),
                ),
                (
                    "03f57d1a813febaccbe6429603f9ec57969511b76cd680452dba91fa01f54e756e"
                        .to_string(),
                    crate::types::U256::from(Uint256::from_u128(200)),
                ),
            ],
            threshold: crate::types::U256::from(Uint256::from_u128(1)),
        };

        (axelar_operators, onchain_operators)
    }

    #[test]
    fn comparing_u256_and_aw_u256_works() {
        let u256 = crate::types::U256::from(Uint256::MAX);
        let aw_u256 = auth_weighted::types::u256::U256::from_le_bytes([255; 32]); // Does not have a U256::MAX
        assert!(u256 == aw_u256);
    }
}
