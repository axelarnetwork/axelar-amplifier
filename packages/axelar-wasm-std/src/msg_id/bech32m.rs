use std::fmt::{self, Display};

use bech32::primitives::decode::CheckedHrpstring;
use bech32::Bech32m;
use error_stack::{bail, ensure, Report, ResultExt};
use regex::Regex;

use super::Error;

#[derive(Debug)]
pub struct Bech32mFormat {
    pub encoded: String,
}

impl Bech32mFormat {
    pub fn new(encoded: String) -> Self {
        Self { encoded }
    }

    pub fn from_str(prefix: &str, length: usize, message_id: &str) -> Result<Self, Report<Error>> {
        // The Bech32m prefix should be between 1 and 83 characters
        ensure!(
            !prefix.is_empty() && prefix.len() <= 83,
            Error::InvalidBech32mFormat("Prefix size should be between 1 and 83".to_string())
        );

        let data_part_length = length.saturating_sub(prefix.len()).saturating_sub(1);
        ensure!(
            data_part_length >= 6,
            Error::InvalidBech32mFormat(
                "The data part should be at least 6 characters long".to_string()
            )
        );

        ensure!(
            prefix.chars().all(|c| { c.is_alphanumeric() }),
            Error::InvalidBech32mFormat(
                "The prefix should contain only Bech32m valid characters".to_string()
            )
        );

        let pattern = format!("^({prefix}1[02-9ac-hj-np-z]{{{data_part_length}}})$");

        let regex = Regex::new(pattern.as_str()).change_context(Error::InvalidBech32mFormat(
            "Failed to create regex".to_string(),
        ))?;

        let (_, [string]) = regex
            .captures(message_id)
            .ok_or(Error::InvalidMessageID {
                id: message_id.to_string(),
                expected_format: format!("Bech32m with '{}' prefix", prefix),
            })?
            .extract();

        verify_bech32m(string, prefix)?;

        Ok(Self {
            encoded: string.to_string(),
        })
    }
}

impl Display for Bech32mFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.encoded)
    }
}

fn verify_bech32m(input: &str, expected_prefix: &str) -> Result<(), Report<Error>> {
    let checked_bech32m = CheckedHrpstring::new::<Bech32m>(input)
        .change_context(Error::InvalidBech32m(input.to_string()))?;

    ensure!(
        checked_bech32m.hrp().as_str() == expected_prefix,
        Error::InvalidBech32m(format!(
            "Expected prefix '{expected_prefix}' not found: '{input}'"
        ))
    );

    if checked_bech32m.data_part_ascii_no_checksum().is_empty() {
        bail!(Error::InvalidBech32m(format!(
            "Message Id is missing the data part: '{input}'"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use bech32::Hrp;
    use rand::Rng;

    use super::*;
    use crate::assert_err_contains;

    #[test]
    fn should_pass_bech32m() {
        let mut rng = rand::rng();

        const CHARS: [char; 32] = [
            'q', 'p', 'z', 'r', 'y', '9', 'x', '8', 'g', 'f', '2', 't', 'v', 'd', 'w', '0', 's',
            '3', 'j', 'n', '5', '4', 'k', 'h', 'c', 'e', '6', 'm', 'u', 'a', '7', 'l',
        ];
        let char_set = CHARS.len();

        for _ in 0..100 {
            let hrp_str = (0..rng.random_range(1..=83))
                .map(|_| CHARS[rng.random_range(0..char_set)])
                .collect::<String>();

            let data = (0..80)
                .map(|_| char::from(rng.random_range(32..=126)))
                .collect::<String>();

            let hrp = Hrp::parse(hrp_str.as_str()).expect("valid hrp");
            let string =
                bech32::encode::<Bech32m>(hrp, data.as_bytes()).expect("failed to encode string");

            assert!(Bech32mFormat::from_str(hrp.as_str(), string.len(), string.as_str()).is_ok());
        }
    }

    #[test]
    fn should_pass_edge_cases() {
        let mut rng = rand::rng();
        let data = (0..80)
            .map(|_| char::from(rng.random_range(32..=126)))
            .collect::<String>();

        // Minimum prefix length
        let hrp_str = "a";
        let hrp = Hrp::parse(hrp_str).expect("valid hrp");
        let string =
            bech32::encode::<Bech32m>(hrp, data.as_bytes()).expect("failed to encode string");

        assert!(Bech32mFormat::from_str(hrp.as_str(), string.len(), string.as_str()).is_ok());

        // Maximum prefix length
        let hrp_string = "a".repeat(83);
        let hrp = Hrp::parse(hrp_string.as_str()).expect("valid hrp");
        let string =
            bech32::encode::<Bech32m>(hrp, data.as_bytes()).expect("failed to encode string");
        assert!(Bech32mFormat::from_str(hrp.as_str(), string.len(), string.as_str()).is_ok());
    }

    #[test]
    fn should_fail_with_invalid_message_id() {
        let string = "at1hs0xk375g4kvw53rcem9nyjsdw5lsv94fl065n77cpt0774nsyysdecaju";
        let hrp = "at";

        assert_err_contains!(
            Bech32mFormat::from_str(hrp, string.len() + 1, string),
            Error,
            Error::InvalidMessageID { .. }
        );

        assert_err_contains!(
            Bech32mFormat::from_str(hrp, string.len() - 1, string),
            Error,
            Error::InvalidMessageID { .. }
        );

        assert_err_contains!(
            Bech32mFormat::from_str("au", string.len(), string),
            Error,
            Error::InvalidMessageID { .. }
        );
    }

    #[test]
    fn should_not_pass_empty_data_part() {
        let hrp_string = "a";
        let hrp = Hrp::parse(hrp_string).expect("valid hrp");
        let string = "a1";
        assert_err_contains!(
            Bech32mFormat::from_str(hrp.as_str(), string.len(), string),
            Error,
            Error::InvalidBech32mFormat(..)
        );

        // Minimum data part length
        let data = "";
        let hrp_string = "a";
        let hrp = Hrp::parse(hrp_string).expect("valid hrp");
        let string =
            bech32::encode::<Bech32m>(hrp, data.as_bytes()).expect("failed to encode string");

        assert_err_contains!(
            Bech32mFormat::from_str(hrp.as_str(), string.len(), string.as_str()),
            Error,
            Error::InvalidBech32m(..)
        );
    }
}
