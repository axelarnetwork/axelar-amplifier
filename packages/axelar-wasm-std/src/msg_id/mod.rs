use std::{fmt::Display, str::FromStr};

use cosmwasm_schema::cw_serde;

use self::tx_hash_event_index::HexTxHashAndEventIndex;

pub mod tx_hash_event_index;

#[cw_serde]
pub enum Error {
    InvalidMessageID { id: String, expected_format: String },
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
pub fn verify_msg_id(message_id: &str, format: &MessageIdFormat) -> Result<(), Error> {
    match format {
        MessageIdFormat::HexTxHashAndEventIndex => {
            HexTxHashAndEventIndex::from_str(message_id).map(|_| ())
        }
        MessageIdFormat::Base58TxDigestAndEventIndex => todo!(),
    }
}
