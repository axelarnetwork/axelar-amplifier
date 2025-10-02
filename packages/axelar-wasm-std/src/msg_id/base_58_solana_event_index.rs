use core::fmt;
use std::fmt::Display;
use std::str::FromStr;

use error_stack::{Report, ResultExt};
use lazy_static::lazy_static;
use regex::Regex;
use serde_with::DeserializeFromStr;

use super::Error;
use crate::nonempty;

type RawSignature = [u8; 64];

#[derive(Debug, Clone, DeserializeFromStr)]
pub struct Base58SolanaTxSignatureAndEventIndex {
    // Base58 decoded bytes of the Solana signature.
    pub raw_signature: RawSignature,
    // index of the inner instruction group in the transaction containing the event
    // must be non-zero as indexing starts at 1 to match the explorer
    pub inner_ix_group_index: nonempty::Uint32,
    // index of the inner instruction in the instruction group containing the event
    // must be non-zero as indexing starts at 1 to match the explorer
    pub inner_ix_index: nonempty::Uint32,
}

impl Base58SolanaTxSignatureAndEventIndex {
    pub fn signature_as_base58(&self) -> nonempty::String {
        bs58::encode(self.raw_signature)
            .into_string()
            .try_into()
            .expect("failed to convert tx hash to non-empty string")
    }

    pub fn new(
        tx_id: impl Into<RawSignature>,
        inner_ix_group_index: nonempty::Uint32,
        inner_ix_index: nonempty::Uint32,
    ) -> Self {
        Self {
            raw_signature: tx_id.into(),
            inner_ix_group_index,
            inner_ix_index,
        }
    }
}

fn decode_b58_signature(signature: &str) -> Result<RawSignature, Report<Error>> {
    Ok(bs58::decode(signature)
        .into_vec()
        .change_context(Error::InvalidTxDigest(signature.to_string()))?
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidTxDigest(signature.to_owned()))?)
}

const PATTERN: &str = "^([1-9A-HJ-NP-Za-km-z]{64,88})-([1-9][0-9]*)\\.([1-9][0-9]*)$";
lazy_static! {
    static ref REGEX: Regex = Regex::new(PATTERN).expect("invalid regex");
}

impl FromStr for Base58SolanaTxSignatureAndEventIndex {
    type Err = Report<Error>;

    fn from_str(message_id: &str) -> Result<Self, Self::Err>
    where
        Self: Sized,
    {
        // the PATTERN has exactly three capture groups, so the groups can be extracted safely
        let (_, [signature, inner_ix_group_index, inner_ix_index]) = REGEX
            .captures(message_id)
            .ok_or(Error::InvalidMessageID {
                id: message_id.to_string(),
                expected_format: PATTERN.to_string(),
            })?
            .extract();

        Ok(Base58SolanaTxSignatureAndEventIndex {
            raw_signature: decode_b58_signature(signature)?,
            inner_ix_group_index: u32::from_str(inner_ix_group_index)
                .map_err(|_| Error::EventIndexOverflow(message_id.to_string()))?
                .try_into()
                .map_err(|_| Error::EventIndexOverflow(message_id.to_string()))?,
            inner_ix_index: u32::from_str(inner_ix_index)
                .map_err(|_| Error::EventIndexOverflow(message_id.to_string()))?
                .try_into()
                .map_err(|_| Error::EventIndexOverflow(message_id.to_string()))?,
        })
    }
}

impl Display for Base58SolanaTxSignatureAndEventIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}-{}.{}",
            bs58::encode(self.raw_signature).into_string(),
            self.inner_ix_group_index.into_inner(),
            self.inner_ix_index.into_inner()
        )
    }
}

#[cfg(test)]
mod tests {

    use hex::ToHex;

    use super::*;

    fn random_bytes() -> RawSignature {
        let mut bytes = [0; 64];
        for b in &mut bytes {
            *b = rand::random();
        }
        bytes
    }

    fn random_tx_digest() -> String {
        bs58::encode(random_bytes()).into_string()
    }

    #[test]
    fn should_parse_msg_id() {
        let res = Base58SolanaTxSignatureAndEventIndex::from_str(
            "4hHzKKdpXH2QMB5Jm11YR48cLqUJb9Cwq2YL3tveVTPeFkZaLP8cdcH5UphVPJ7kYwCUCRLnywd3xkUhb4ZYWtf5-1.1",
        );
        assert!(res.is_ok());

        for _ in 0..1000 {
            let tx_digest = random_tx_digest();
            let inner_ix_group_index = rand::random::<u32>() % 1000 + 1;
            let inner_ix_index = rand::random::<u32>() % 1000 + 1;
            let msg_id = format!("{}-{}.{}", tx_digest, inner_ix_group_index, inner_ix_index);

            let res = Base58SolanaTxSignatureAndEventIndex::from_str(&msg_id);
            let parsed = res.unwrap();
            assert_eq!(
                parsed.inner_ix_group_index.into_inner(),
                inner_ix_group_index
            );
            assert_eq!(parsed.inner_ix_index.into_inner(), inner_ix_index);
            assert_eq!(parsed.signature_as_base58(), tx_digest.as_str());
            assert_eq!(parsed.to_string(), msg_id);
        }
    }

    #[test]
    fn should_not_parse_msg_id_with_wrong_length_base58_tx_digest() {
        let tx_digest = random_tx_digest();
        let inner_ix_group_index = rand::random::<u32>() % 1000;
        let inner_ix_index = rand::random::<u32>() % 1000 + 1;

        // too long
        let msg_id = format!(
            "{}{}-{}.{}",
            tx_digest, tx_digest, inner_ix_group_index, inner_ix_index
        );
        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&msg_id);
        assert!(res.is_err());

        // too short
        let msg_id = format!(
            "{}-{}.{}",
            &tx_digest[0..63],
            inner_ix_group_index,
            inner_ix_index
        );
        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&msg_id);
        assert!(res.is_err());
    }

    #[test]
    fn leading_ones_should_not_be_ignored() {
        let tx_digest = random_tx_digest();
        let inner_ix_group_index = rand::random::<u32>() % 1000;
        let inner_ix_index = rand::random::<u32>() % 1000 + 1;

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!(
            "1{}-{}.{}",
            tx_digest, inner_ix_group_index, inner_ix_index
        ));
        assert!(res.is_err());

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!(
            "11{}-{}.{}",
            tx_digest, inner_ix_group_index, inner_ix_index
        ));
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_correct_length_base58_but_wrong_length_hex() {
        // this is 88 chars and valid base58, but will decode to 66 bytes
        // the leading 1s are encoded as 00 in hex and thus result in too many bytes
        let tx_digest = "1111KKdpXH2QMB5Jm11YR48cLqUJb9Cwq2YL3tveVTPeFkZaLP8cdcH5UphVPJ7kYwCUCRLnywd3xkUhb4ZYWtf5";
        let inner_ix_group_index = rand::random::<u32>() % 1000;
        let inner_ix_index = rand::random::<u32>() % 1000 + 1;
        let msg_id = format!("{}-{}.{}", tx_digest, inner_ix_group_index, inner_ix_index);

        assert!(REGEX.captures(&msg_id).is_some());
        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&msg_id);
        assert!(res.is_err());

        // this is 88 chars and valid base 58, but will encode to 65 bytes
        // (z is the largest base58 digit, and so this will overflow 2^512)
        let tx_digest = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        assert_eq!(tx_digest.len(), 88);
        let msg_id = format!("{}-{}.{}", tx_digest, inner_ix_group_index, inner_ix_index);

        assert!(REGEX.captures(&msg_id).is_some());
        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&msg_id);
        assert!(res.is_err());
    }

    #[test]
    fn should_parse_msg_id_less_than_88_chars_tx_digest() {
        // the tx digest can be less than 88 chars in the presence of leading 1s (00 in hex)
        let tx_digest =
            "1111KKdpXH2QMB5Jm11YR48cLqUJb9Cwq2YL3tveVTPeFkZaLP8cdcH5UphVPJ7kYwCUCRLnywd3xkUhb4ZYW";
        assert!(tx_digest.len() < 88);
        let inner_ix_group_index = rand::random::<u32>() % 1000;
        let inner_ix_index = rand::random::<u32>() % 1000 + 1;

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!(
            "{}-{}.{}",
            tx_digest, inner_ix_group_index, inner_ix_index
        ));
        assert!(res.is_ok());
    }

    #[test]
    fn should_not_parse_msg_id_with_invalid_base58() {
        let tx_digest = random_tx_digest();
        let inner_ix_group_index = rand::random::<u32>() % 1000;
        let inner_ix_index = rand::random::<u32>() % 1000 + 1;

        // 0, O and I are invalid base58 chars
        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!(
            "0{}-{}.{}",
            &tx_digest[1..],
            inner_ix_group_index,
            inner_ix_index
        ));
        assert!(res.is_err());

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!(
            "I{}-{}.{}",
            &tx_digest[1..],
            inner_ix_group_index,
            inner_ix_index
        ));
        assert!(res.is_err());

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!(
            "O{}-{}.{}",
            &tx_digest[1..],
            inner_ix_group_index,
            inner_ix_index
        ));
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_hex_tx_digest() {
        let tx_digest = random_tx_digest();
        let inner_ix_group_index = rand::random::<u32>() % 1000;
        let inner_ix_index = rand::random::<u32>() % 1000 + 1;
        let tx_digest_hex = bs58::decode(tx_digest)
            .into_vec()
            .unwrap()
            .encode_hex::<String>();
        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!(
            "{}-{}.{}",
            tx_digest_hex, inner_ix_group_index, inner_ix_index
        ));
        assert!(res.is_err());

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!(
            "0x{}-{}.{}",
            tx_digest_hex, inner_ix_group_index, inner_ix_index
        ));
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_missing_instruction_indices() {
        let msg_id = random_tx_digest();
        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&msg_id);
        assert!(res.is_err());

        let msg_id = format!("{}-", random_tx_digest());
        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&msg_id);
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_wrong_separator() {
        let tx_digest = random_tx_digest();
        let inner_ix_group_index = rand::random::<u32>() % 1000;
        let inner_ix_index = rand::random::<u32>() % 1000 + 1;

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!(
            "{}:{}.{}",
            tx_digest, inner_ix_group_index, inner_ix_index
        ));
        assert!(res.is_err());

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!(
            "{}_{}.{}",
            tx_digest, inner_ix_group_index, inner_ix_index
        ));
        assert!(res.is_err());

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!(
            "{}+{}.{}",
            tx_digest, inner_ix_group_index, inner_ix_index
        ));
        assert!(res.is_err());

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!(
            "{}-{}:{}",
            tx_digest, inner_ix_group_index, inner_ix_index
        ));
        assert!(res.is_err());

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!(
            "{}-{}_{}",
            tx_digest, inner_ix_group_index, inner_ix_index
        ));
        assert!(res.is_err());

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!(
            "{}{}{}",
            tx_digest, inner_ix_group_index, inner_ix_index
        ));
        assert!(res.is_err());

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!(
            "{}-{}",
            tx_digest, inner_ix_group_index
        ));
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_event_index_with_leading_zeroes() {
        let tx_digest = random_tx_digest();
        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!("{}-01.5", tx_digest));
        assert!(res.is_err());

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!("{}-5.01", tx_digest));
        assert!(res.is_err());

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!("{}-01.01", tx_digest));
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_zero_inner_ix_index() {
        let tx_digest = random_tx_digest();

        // inner_ix_index cannot be 0 as events are always inner instructions
        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!("{}-1.0", tx_digest));
        assert!(res.is_err());

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!("{}-5.0", tx_digest));
        assert!(res.is_err());

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!("{}-999.0", tx_digest));
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_zero_inner_ix_group_index() {
        let tx_digest = random_tx_digest();

        // inner_ix_group_index cannot be 0 as indexing starts at 1 to match the explorer
        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!("{}-0.1", tx_digest));
        assert!(res.is_err());

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!("{}-0.5", tx_digest));
        assert!(res.is_err());

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!("{}-0.999", tx_digest));
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_non_integer_event_index() {
        let tx_digest = random_tx_digest();

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!("{}-1.5.0", tx_digest));
        assert!(res.is_err());

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!("{}-0x00.0", tx_digest));
        assert!(res.is_err());

        let res =
            Base58SolanaTxSignatureAndEventIndex::from_str(&format!("{}-foobar.0", tx_digest));
        assert!(res.is_err());

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!("{}-true.0", tx_digest));
        assert!(res.is_err());

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!("{}-0.1.5", tx_digest));
        assert!(res.is_err());

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!("{}-0.0x00", tx_digest));
        assert!(res.is_err());

        let res =
            Base58SolanaTxSignatureAndEventIndex::from_str(&format!("{}-0.foobar", tx_digest));
        assert!(res.is_err());

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!("{}-0.true", tx_digest));
        assert!(res.is_err());

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!("{}-.", tx_digest));
        assert!(res.is_err());

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!("{}-0.", tx_digest));
        assert!(res.is_err());

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!("{}-", tx_digest));
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_overflowing_event_index() {
        let index: u64 = u64::MAX;
        let tx_digest = random_tx_digest();

        let res =
            Base58SolanaTxSignatureAndEventIndex::from_str(&format!("{}-{}.0", tx_digest, index));
        assert!(res.is_err());

        let res =
            Base58SolanaTxSignatureAndEventIndex::from_str(&format!("{}-0.{}", tx_digest, index));
        assert!(res.is_err());

        let res = Base58SolanaTxSignatureAndEventIndex::from_str(&format!(
            "{}-{}.{}",
            tx_digest, index, index
        ));
        assert!(res.is_err());
    }

    #[test]
    fn trimming_leading_ones_should_change_bytes() {
        for _ in 0..100 {
            let mut bytes = random_bytes();

            // set a random (non-zero) number of leading bytes to 0
            let leading_zeroes = rand::random::<usize>() % bytes.len() + 1;
            for b in bytes.iter_mut().take(leading_zeroes) {
                *b = 0;
            }

            let b58 = bs58::encode(&bytes).into_string();

            // verify the base58 has the expected number of leading 1's
            for c in b58.chars().take(leading_zeroes) {
                assert_eq!(c, '1');
            }

            // trim a random (non-zero) number of leading 1's
            let trim = rand::random::<usize>() % leading_zeroes + 1;

            // converting back to bytes should yield a different result
            let decoded = bs58::decode(&b58[trim..]).into_vec().unwrap();
            assert_ne!(bytes.to_vec(), decoded);
        }
    }
}
