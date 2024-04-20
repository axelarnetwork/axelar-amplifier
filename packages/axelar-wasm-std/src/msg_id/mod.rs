use std::{fmt::Display, str::FromStr};

use cosmwasm_schema::cw_serde;
use error_stack::Report;

use self::{
    base_58_event_index::Base58TxDigestAndEventIndex, tx_hash_event_index::HexTxHashAndEventIndex,
};

pub mod base_58_event_index;
pub mod tx_hash_event_index;

#[derive(thiserror::Error)]
#[cw_serde]
pub enum Error {
    #[error("invalid message id '{id}', expected format: {expected_format}")]
    InvalidMessageID { id: String, expected_format: String },
    #[error("event index in message id '{0}' is larger than u32 max value")]
    EventIndexOverflow(String),
    #[error("invalid transaction hash in message id '{0}'")]
    InvalidTxHash(String),
    #[error("invalid tx digest in message id '{0}'")]
    InvalidTxDigest(String),
}

/// Any message id format must implement this trait.
/// The implementation must satisfy the following invariants:
///
/// * if m1 != m2 then from_str(m1) != from_str(m2) (two different strings cannot parse to the same message id)
///
/// * if t1 != t2 then to_string(t1) != to_string(t2) (two different message ids cannot serialize to the same string)
///
/// There should be only one string that can identify a given message.
/// Take extra care to handle things like leading 0s, casing, etc.
pub trait MessageId: FromStr + Display {}

/// enum to pass to the router when registering a new chain
#[cw_serde]
pub enum MessageIdFormat {
    HexTxHashAndEventIndex,
    Base58TxDigestAndEventIndex,
}

// function the router calls to verify msg ids
pub fn verify_msg_id(message_id: &str, format: &MessageIdFormat) -> Result<(), Report<Error>> {
    match format {
        MessageIdFormat::HexTxHashAndEventIndex => {
            HexTxHashAndEventIndex::from_str(message_id).map(|_| ())
        }
        MessageIdFormat::Base58TxDigestAndEventIndex => {
            Base58TxDigestAndEventIndex::from_str(message_id).map(|_| ())
        }
    }
}
