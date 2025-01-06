use core::fmt;
use std::fmt::Display;
use std::str::FromStr;

use cosmwasm_std::HexBinary;
use error_stack::Report;
use lazy_static::lazy_static;
use regex::Regex;
use serde_with::DeserializeFromStr;
use starknet_checked_felt::CheckedFelt;

use super::Error;
use crate::nonempty;

#[derive(Debug, DeserializeFromStr, Clone)]
pub struct FieldElementAndEventIndex {
    pub tx_hash: CheckedFelt,
    pub event_index: u64,
}

impl FieldElementAndEventIndex {
    pub fn tx_hash_as_hex(&self) -> nonempty::String {
        format!("0x{}", self.tx_hash_as_hex_no_prefix())
            .try_into()
            .expect("failed to convert tx hash to non-empty string")
    }

    pub fn tx_hash_as_hex_no_prefix(&self) -> nonempty::String {
        HexBinary::from(self.tx_hash.to_bytes_be())
            .to_hex()
            .to_string()
            .try_into()
            .expect("failed to convert tx hash to non-empty string")
    }

    pub fn new<T: Into<CheckedFelt> + FromStr>(
        tx_id: T,
        event_index: impl Into<u64>,
    ) -> Result<Self, Error> {
        Ok(Self {
            tx_hash: tx_id.into(),
            event_index: event_index.into(),
        })
    }
}

// A valid field element is max 252 bits, meaning max 63 hex characters after 0x.
// We require the hex to be 64 characters, meaning that it should be padded with zeroes in order
// for us to consider it valid.
const PATTERN: &str = "^(0x0[0-9a-f]{63})-(0|[1-9][0-9]*)$";
lazy_static! {
    static ref REGEX: Regex = Regex::new(PATTERN).expect("invalid regex");
}

impl FromStr for FieldElementAndEventIndex {
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
        let felt = CheckedFelt::from_str(tx_id)
            .map_err(|e| Error::InvalidFieldElement(format!("{}: {}", e, tx_id)))?;

        Ok(FieldElementAndEventIndex {
            tx_hash: felt,
            event_index: event_index
                .parse()
                .map_err(|_| Error::EventIndexOverflow(message_id.to_string()))?,
        })
    }
}

// pad the FieldElement with zeroes
impl Display for FieldElementAndEventIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:064x}-{}", self.tx_hash, self.event_index)
    }
}

impl From<FieldElementAndEventIndex> for nonempty::String {
    fn from(msg_id: FieldElementAndEventIndex) -> Self {
        msg_id
            .to_string()
            .try_into()
            .expect("failed to convert msg id to non-empty string")
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::U256;
    use rand::Rng;

    use super::*;

    fn random_hash() -> String {
        // Generate a random 256-bit value
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        let number = U256::from_be_bytes::<32>(bytes);
        let max: U256 = U256::from_be_bytes::<32>([
            8, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);

        let result = number.checked_rem(max).expect("modulo operation failed");

        format!("0x{:064x}", result)
    }

    fn random_event_index() -> u64 {
        rand::random()
    }

    #[test]
    fn should_parse_msg_id() {
        let res = FieldElementAndEventIndex::from_str(
            "0x0670d1dd42a19cb229bb4378b58b9c3e76aa43edaaea46845cd8c456c1224d89-0",
        );
        assert!(res.is_ok());

        for _ in 0..1000 {
            let tx_hash = random_hash();
            let event_index = random_event_index();
            let msg_id = format!("{}-{}", tx_hash, event_index);

            let res = FieldElementAndEventIndex::from_str(&msg_id);
            let parsed = res.unwrap();
            assert_eq!(parsed.event_index, event_index);
            assert_eq!(parsed.tx_hash_as_hex(), tx_hash.try_into().unwrap(),);
            assert_eq!(parsed.to_string(), msg_id);
        }
    }

    #[test]
    fn should_not_parse_msg_id_overflowing_felt() {
        let res = FieldElementAndEventIndex::from_str(
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff-0",
        );
        assert!(res.is_err());

        // Felt::MAX + 1
        let res = FieldElementAndEventIndex::from_str(
            "0x080000006b9f1bed878fcc665f2ca1a6afd545a6b864d8400000000000000001-0",
        );
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_63_or_62_chars() {
        let res = FieldElementAndEventIndex::from_str(
            "0x670d1dd42a19cb229bb4378b58b9c3e76aa43edaaea46845cd8c456c1224d89-0",
        );
        assert!(res.is_err());

        let res = FieldElementAndEventIndex::from_str(
            "0x17f60b1e54f3b012bffc2b328070fde2b5dae12220c985f098fb8e36338472-0",
        );
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_wrong_length_tx_hash() {
        let tx_hash = random_hash();
        // too long
        let res = FieldElementAndEventIndex::from_str(&format!("{}ff-{}", tx_hash, 1));
        assert!(res.is_err());

        // too short
        let res = FieldElementAndEventIndex::from_str(&format!(
            "{}-{}",
            &tx_hash[..tx_hash.len() - 2],
            1
        ));
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_uppercase_tx_hash() {
        let tx_hash = &random_hash()[2..];
        let res =
            FieldElementAndEventIndex::from_str(&format!("0x{}-{}", tx_hash.to_uppercase(), 1));
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_non_hex_tx_hash() {
        let msg_id = "82GKYvWv5EKm7jnYksHoh3u5M2RxHN2boPreM8Df4ej9-1";
        let res = FieldElementAndEventIndex::from_str(msg_id);
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_without_0x() {
        let msg_id = "7cedbb3799cd99636045c84c5c55aef8a138f107ac8ba53a08cad1070ba4385b-1";
        let res = FieldElementAndEventIndex::from_str(msg_id);
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_missing_event_index() {
        let msg_id = random_hash();
        let res = FieldElementAndEventIndex::from_str(&msg_id);
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_wrong_separator() {
        let tx_hash = random_hash();
        let event_index = random_event_index();

        let res = FieldElementAndEventIndex::from_str(&format!("{}:{}", tx_hash, event_index));
        assert!(res.is_err());

        let res = FieldElementAndEventIndex::from_str(&format!("{}_{}", tx_hash, event_index));
        assert!(res.is_err());

        let res = FieldElementAndEventIndex::from_str(&format!("{}+{}", tx_hash, event_index));
        assert!(res.is_err());

        let res = FieldElementAndEventIndex::from_str(&format!("{}{}", tx_hash, event_index));
        assert!(res.is_err());

        for _ in 0..10 {
            let random_sep: char = rand::random();
            if random_sep == '-' {
                continue;
            }
            let res = FieldElementAndEventIndex::from_str(&format!(
                "{}{}{}",
                tx_hash, random_sep, event_index
            ));
            assert!(res.is_err());
        }
    }

    #[test]
    fn should_not_parse_msg_id_with_event_index_with_leading_zeroes() {
        let tx_hash = random_hash();
        let res = FieldElementAndEventIndex::from_str(&format!("{}-01", tx_hash));
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_non_integer_event_index() {
        let tx_hash = random_hash();
        let res = FieldElementAndEventIndex::from_str(&format!("{}-1.0", tx_hash));
        assert!(res.is_err());

        let res = FieldElementAndEventIndex::from_str(&format!("{}-0x00", tx_hash));
        assert!(res.is_err());

        let res = FieldElementAndEventIndex::from_str(&format!("{}-foobar", tx_hash));
        assert!(res.is_err());

        let res = FieldElementAndEventIndex::from_str(&format!("{}-true", tx_hash));
        assert!(res.is_err());

        let res = FieldElementAndEventIndex::from_str(&format!("{}-", tx_hash));
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_overflowing_event_index() {
        let event_index: u64 = u64::MAX;
        let tx_hash = random_hash();
        let res = FieldElementAndEventIndex::from_str(&format!("{}-{}1", tx_hash, event_index));
        assert!(res.is_err());
    }
}
