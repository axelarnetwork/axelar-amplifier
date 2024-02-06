use axelar_wasm_std::voting::Vote;
use base64::Engine as _;
use borsh::{BorshDeserialize, BorshSerialize};

use base64::{self, engine::general_purpose};
use thiserror::Error;
use tracing::info;

use crate::handlers::solana_verify_worker_set::WorkerSetConfirmation;

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

#[derive(Error, Debug)]
pub enum VerificationError {
    #[error("Failed to parse tx log messages")]
    NoLogMessages,
    #[error("Tried to get gw event from program logs, but couldn't find anything.")]
    NoGatewayEventFound,
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

    if worker_set.tx_id != sol_tx.transaction.signatures[0] {
        info!(tx_id = &worker_set.tx_id, "tx_id do not match");
        return Vote::FailedOnChain;
    }

    let verified = verify_worker_set_data(&worker_set, &account_info);

    match verified {
        true => Vote::SucceededOnChain,
        false => Vote::FailedOnChain,
    }
}

fn verify_worker_set_data(worker_set: &WorkerSetConfirmation, account_info: &AccountInfo) -> bool {
    todo!("Properly parse account info and cross check with axelar worker_set")
}
