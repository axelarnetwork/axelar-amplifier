use core::fmt;
use std::fmt::Display;
use std::str::FromStr;

use cosmwasm_std::HexBinary;
use error_stack::{Report, ResultExt};
use lazy_static::lazy_static;
use regex::Regex;

use super::Error;
use crate::hash::Hash;
use crate::nonempty;

pub struct HexTxHashAndEventIndex {
    pub tx_hash: Hash,
    pub event_index: u32,
}

impl HexTxHashAndEventIndex {
    pub fn tx_hash_as_hex(&self) -> nonempty::String {
        format!("0x{}", HexBinary::from(self.tx_hash).to_hex())
            .try_into()
            .expect("failed to convert tx hash to non-empty string")
    }

    pub fn new(tx_id: impl Into<[u8; 32]>, event_index: impl Into<u32>) -> Self {
        Self {
            tx_hash: tx_id.into(),
            event_index: event_index.into(),
        }
    }
}

const PATTERN: &str = "^(0x[0-9a-f]{64})-(0|[1-9][0-9]*)$";
lazy_static! {
    static ref REGEX: Regex = Regex::new(PATTERN).expect("invalid regex");
}

impl FromStr for HexTxHashAndEventIndex {
    type Err = Report<Error>;

    fn from_str(message_id: &str) -> Result<Self, Self::Err>
    where
        Self: Sized,
    {
        // the PATTERN has exactly two capture groups, so the groups can be extracted safely
        let (_, [tx_id, event_index]) = REGEX
            .captures(message_id)
            .ok_or(Error::InvalidMessageID {
                id: message_id.to_string(),
                expected_format: PATTERN.to_string(),
            })?
            .extract();
        Ok(HexTxHashAndEventIndex {
            tx_hash: HexBinary::from_hex(&tx_id[2..])
                .change_context(Error::InvalidTxHash(message_id.to_string()))?
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidTxHash(message_id.to_string()))?,
            event_index: event_index
                .parse()
                .map_err(|_| Error::EventIndexOverflow(message_id.to_string()))?,
        })
    }
}

impl Display for HexTxHashAndEventIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "0x{}-{}",
            HexBinary::from(self.tx_hash).to_hex(),
            self.event_index
        )
    }
}

impl From<HexTxHashAndEventIndex> for nonempty::String {
    fn from(msg_id: HexTxHashAndEventIndex) -> Self {
        msg_id
            .to_string()
            .try_into()
            .expect("failed to convert msg id to non-empty string")
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn random_hash() -> String {
        let mut bytes = vec![];
        for _ in 0..32 {
            let byte: u8 = rand::random();
            bytes.push(byte)
        }
        format!("0x{}", HexBinary::from(bytes).to_hex())
    }

    fn random_event_index() -> u32 {
        rand::random()
    }

    #[test]
    fn should_parse_msg_id() {
        let res = HexTxHashAndEventIndex::from_str(
            "0x7cedbb3799cd99636045c84c5c55aef8a138f107ac8ba53a08cad1070ba4385b-0",
        );
        assert!(res.is_ok());

        for _ in 0..1000 {
            let tx_hash = random_hash();
            let event_index = random_event_index();
            let msg_id = format!("{}-{}", tx_hash, event_index);

            let res = HexTxHashAndEventIndex::from_str(&msg_id);
            let parsed = res.unwrap();
            assert_eq!(parsed.event_index, event_index);
            assert_eq!(parsed.tx_hash_as_hex(), tx_hash.try_into().unwrap(),);
            assert_eq!(parsed.to_string(), msg_id);
        }
    }

    #[test]
    fn should_not_parse_msg_id_with_wrong_length_tx_hash() {
        let tx_hash = random_hash();
        // too long
        let res = HexTxHashAndEventIndex::from_str(&format!("{}ff-{}", tx_hash, 1));
        assert!(res.is_err());

        // too short
        let res =
            HexTxHashAndEventIndex::from_str(&format!("{}-{}", &tx_hash[..tx_hash.len() - 2], 1));
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_uppercase_tx_hash() {
        let tx_hash = &random_hash()[2..];
        let res = HexTxHashAndEventIndex::from_str(&format!("0x{}-{}", tx_hash.to_uppercase(), 1));
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_non_hex_tx_hash() {
        let msg_id = "82GKYvWv5EKm7jnYksHoh3u5M2RxHN2boPreM8Df4ej9-1";
        let res = HexTxHashAndEventIndex::from_str(msg_id);
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_without_0x() {
        let msg_id = "7cedbb3799cd99636045c84c5c55aef8a138f107ac8ba53a08cad1070ba4385b-1";
        let res = HexTxHashAndEventIndex::from_str(msg_id);
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_missing_event_index() {
        let msg_id = random_hash();
        let res = HexTxHashAndEventIndex::from_str(&msg_id);
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_wrong_separator() {
        let tx_hash = random_hash();
        let event_index = random_event_index();

        let res = HexTxHashAndEventIndex::from_str(&format!("{}:{}", tx_hash, event_index));
        assert!(res.is_err());

        let res = HexTxHashAndEventIndex::from_str(&format!("{}_{}", tx_hash, event_index));
        assert!(res.is_err());

        let res = HexTxHashAndEventIndex::from_str(&format!("{}+{}", tx_hash, event_index));
        assert!(res.is_err());

        let res = HexTxHashAndEventIndex::from_str(&format!("{}{}", tx_hash, event_index));
        assert!(res.is_err());

        for _ in 0..10 {
            let random_sep: char = rand::random();
            if random_sep == '-' {
                continue;
            }
            let res = HexTxHashAndEventIndex::from_str(&format!(
                "{}{}{}",
                tx_hash, random_sep, event_index
            ));
            assert!(res.is_err());
        }
    }

    #[test]
    fn should_not_parse_msg_id_with_event_index_with_leading_zeroes() {
        let tx_hash = random_hash();
        let res = HexTxHashAndEventIndex::from_str(&format!("{}-01", tx_hash));
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_non_integer_event_index() {
        let tx_hash = random_hash();
        let res = HexTxHashAndEventIndex::from_str(&format!("{}-1.0", tx_hash));
        assert!(res.is_err());

        let res = HexTxHashAndEventIndex::from_str(&format!("{}-0x00", tx_hash));
        assert!(res.is_err());

        let res = HexTxHashAndEventIndex::from_str(&format!("{}-foobar", tx_hash));
        assert!(res.is_err());

        let res = HexTxHashAndEventIndex::from_str(&format!("{}-true", tx_hash));
        assert!(res.is_err());

        let res = HexTxHashAndEventIndex::from_str(&format!("{}-", tx_hash));
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_overflowing_event_index() {
        let event_index: u64 = u64::MAX;
        let tx_hash = random_hash();
        let res = HexTxHashAndEventIndex::from_str(&format!("{}-{}", tx_hash, event_index));
        assert!(res.is_err());
    }
}
