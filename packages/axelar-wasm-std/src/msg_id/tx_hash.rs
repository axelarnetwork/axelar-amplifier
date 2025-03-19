use core::fmt;
use std::fmt::Display;
use std::str::FromStr;

use cosmwasm_std::HexBinary;
use error_stack::{ensure, Report, ResultExt};
use lazy_static::lazy_static;
use regex::Regex;

use super::Error;
use crate::hash::Hash;
use crate::nonempty;

pub struct HexTxHash {
    pub tx_hash: Hash,
}

impl HexTxHash {
    pub fn tx_hash_as_hex(&self) -> nonempty::String {
        format!("0x{}", HexBinary::from(self.tx_hash).to_hex())
            .try_into()
            .expect("failed to convert tx hash to non-empty string")
    }

    pub fn new(tx_id: impl Into<[u8; 32]>) -> Self {
        Self {
            tx_hash: tx_id.into(),
        }
    }
}

const PATTERN: &str = "^0x[0-9a-f]{64}$";
lazy_static! {
    static ref REGEX: Regex = Regex::new(PATTERN).expect("invalid regex");
}

impl FromStr for HexTxHash {
    type Err = Report<Error>;

    fn from_str(message_id: &str) -> Result<Self, Self::Err>
    where
        Self: Sized,
    {
        // the PATTERN has exactly two capture groups, so the groups can be extracted safely
        ensure!(
            REGEX.is_match(message_id),
            Error::InvalidMessageID {
                id: message_id.to_string(),
                expected_format: PATTERN.to_string(),
            }
        );
        Ok(HexTxHash {
            tx_hash: HexBinary::from_hex(&message_id[2..])
                .change_context(Error::InvalidTxHash(message_id.to_string()))?
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidTxHash(message_id.to_string()))?,
        })
    }
}

impl Display for HexTxHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", HexBinary::from(self.tx_hash).to_hex())
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

    #[test]
    fn should_parse_msg_id() {
        let res = HexTxHash::from_str(
            "0x7cedbb3799cd99636045c84c5c55aef8a138f107ac8ba53a08cad1070ba4385b",
        );
        assert!(res.is_ok());

        for _ in 0..1000 {
            let msg_id = random_hash();

            let res = HexTxHash::from_str(&msg_id);
            let parsed = res.unwrap();
            assert_eq!(parsed.tx_hash_as_hex(), msg_id.clone().try_into().unwrap());
            assert_eq!(parsed.to_string(), msg_id);
        }
    }

    #[test]
    fn should_not_parse_msg_id_with_wrong_length_tx_hash() {
        let tx_hash = random_hash();
        // too long
        let res = HexTxHash::from_str(&format!("{}ff", tx_hash));
        assert!(res.is_err());

        // too short
        let res = HexTxHash::from_str(&tx_hash[..tx_hash.len() - 2]);
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_uppercase_tx_hash() {
        let tx_hash = &random_hash()[2..];
        let res = HexTxHash::from_str(&format!("0x{}", tx_hash.to_uppercase()));
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_non_hex_tx_hash() {
        let msg_id = "82GKYvWv5EKm7jnYksHoh3u5M2RxHN2boPreM8Df4ej9";
        let res = HexTxHash::from_str(msg_id);
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_without_0x() {
        let msg_id = "7cedbb3799cd99636045c84c5c55aef8a138f107ac8ba53a08cad1070ba4385b";
        let res = HexTxHash::from_str(msg_id);
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_event_index() {
        let tx_hash = random_hash();
        let res = HexTxHash::from_str(&format!("{}-1", tx_hash));
        assert!(res.is_err());
    }
}
