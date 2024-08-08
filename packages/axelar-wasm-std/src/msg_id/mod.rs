use std::fmt::Display;
use std::str::FromStr;

use cosmwasm_schema::cw_serde;
use error_stack::Report;

pub use self::base_58_event_index::Base58TxDigestAndEventIndex;
pub use self::base_58_solana_event_index::Base58SolanaTxSignatureAndEventIndex;
pub use self::tx_hash::HexTxHash;
pub use self::tx_hash_event_index::HexTxHashAndEventIndex;

mod base_58_event_index;
mod base_58_solana_event_index;
mod tx_hash;
mod tx_hash_event_index;

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
    Base58SolanaTxSignatureAndEventIndex,
    HexTxHash,
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
        MessageIdFormat::Base58SolanaTxSignatureAndEventIndex => {
            Base58SolanaTxSignatureAndEventIndex::from_str(message_id).map(|_| ())
        }
        MessageIdFormat::HexTxHash => HexTxHash::from_str(message_id).map(|_| ()),
    }
}

#[cfg(test)]
mod test {
    use super::tx_hash_event_index::HexTxHashAndEventIndex;
    use crate::msg_id::base_58_event_index::Base58TxDigestAndEventIndex;
    use crate::msg_id::{verify_msg_id, MessageIdFormat};

    #[test]
    fn should_verify_hex_tx_hash_event_index_msg_id() {
        let msg_id = HexTxHashAndEventIndex {
            tx_hash: [1; 32],
            event_index: 0,
        }
        .to_string();
        assert!(verify_msg_id(&msg_id, &MessageIdFormat::HexTxHashAndEventIndex).is_ok());
    }

    #[test]
    fn should_verify_base_58_tx_digest_event_index_msg_id() {
        let msg_id = Base58TxDigestAndEventIndex {
            tx_digest: [1; 32],
            event_index: 0,
        }
        .to_string();
        assert!(verify_msg_id(&msg_id, &MessageIdFormat::Base58TxDigestAndEventIndex).is_ok());
    }

    #[test]
    fn should_not_verify_invalid_msg_id() {
        let msg_id = "foobar";
        assert!(verify_msg_id(msg_id, &MessageIdFormat::HexTxHashAndEventIndex).is_err());
    }

    #[test]
    fn should_not_verify_msg_id_with_wrong_format() {
        let msg_id = HexTxHashAndEventIndex {
            tx_hash: [1; 32],
            event_index: 0,
        }
        .to_string();
        assert!(verify_msg_id(&msg_id, &MessageIdFormat::Base58TxDigestAndEventIndex).is_err());

        let msg_id = Base58TxDigestAndEventIndex {
            tx_digest: [1; 32],
            event_index: 0,
        }
        .to_string();
        assert!(verify_msg_id(&msg_id, &MessageIdFormat::HexTxHashAndEventIndex).is_err());
    }
}
