use std::convert::{TryFrom, TryInto};
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;
use std::{fmt, ops};

use cosmrs::proto;
use error_stack::{ensure, Report, Result, ResultExt};
use report::ResultCompatExt;
use serde::{Deserialize, Serialize};
use serde_with::SerializeDisplay;
use thiserror::Error;
use tracing::error;

use crate::broadcaster::dec_coin::Error::*;

#[derive(Error, Debug)]
pub enum Error {
    #[error("parsing failed")]
    ParsingFailed,
    #[error("amount is not a number")]
    AmountIsNaN,
    #[error("denomination is empty")]
    DenomIsEmpty,
}

#[derive(SerializeDisplay, Deserialize, Clone, Debug, PartialEq, PartialOrd)]
#[serde(try_from = "String")]
pub struct DecCoin {
    pub denom: Denom,
    pub amount: FiniteAmount,
}

impl DecCoin {
    pub fn new(amount: f64, denom: &str) -> Result<Self, Error> {
        Ok(DecCoin {
            amount: amount.try_into()?,
            denom: denom.parse()?,
        })
    }
}

impl TryFrom<proto::cosmos::base::v1beta1::DecCoin> for DecCoin {
    type Error = Report<Error>;

    fn try_from(proto: proto::cosmos::base::v1beta1::DecCoin) -> Result<DecCoin, Error> {
        DecCoin::try_from(&proto)
    }
}

impl TryFrom<&proto::cosmos::base::v1beta1::DecCoin> for DecCoin {
    type Error = Report<Error>;

    fn try_from(proto: &proto::cosmos::base::v1beta1::DecCoin) -> Result<DecCoin, Error> {
        Ok(DecCoin {
            amount: proto.amount.parse()?,
            denom: proto.denom.parse()?,
        })
    }
}

impl From<DecCoin> for proto::cosmos::base::v1beta1::DecCoin {
    fn from(coin: DecCoin) -> proto::cosmos::base::v1beta1::DecCoin {
        proto::cosmos::base::v1beta1::DecCoin::from(&coin)
    }
}

impl From<&DecCoin> for proto::cosmos::base::v1beta1::DecCoin {
    fn from(coin: &DecCoin) -> proto::cosmos::base::v1beta1::DecCoin {
        proto::cosmos::base::v1beta1::DecCoin {
            denom: coin.denom.to_string(),
            amount: coin.amount.to_string(),
        }
    }
}

impl TryFrom<String> for DecCoin {
    type Error = Report<Error>;

    fn try_from(s: String) -> core::result::Result<Self, Self::Error> {
        s.as_str().try_into()
    }
}

impl TryFrom<&str> for DecCoin {
    type Error = Report<Error>;

    fn try_from(s: &str) -> core::result::Result<Self, Self::Error> {
        let amount_index = s.find(char::is_numeric);
        let denom_index = s.find(char::is_alphabetic);

        match (amount_index, denom_index) {
            (Some(0), Some(denom_index)) => {
                let (amount, denom) = s.split_at(denom_index);
                Ok(DecCoin {
                    denom: denom.parse()?,
                    amount: amount.parse()?,
                })
            }
            _ => Err(Report::from(ParsingFailed)),
        }
    }
}

impl Display for DecCoin {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // See: https://github.com/cosmos/cosmos-sdk/blob/c4864e9f85011b3e971885ea995a0021c01a885d/types/dec_coin.go#L134
        write!(f, "{}{}", self.amount, self.denom)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, PartialOrd, Copy)]
pub struct FiniteAmount(f64);

impl TryFrom<f64> for FiniteAmount {
    type Error = Report<Error>;

    fn try_from(value: f64) -> std::result::Result<Self, Self::Error> {
        ensure!(!value.is_nan() && !value.is_infinite(), AmountIsNaN);
        Ok(FiniteAmount(value))
    }
}

impl FromStr for FiniteAmount {
    type Err = Report<Error>;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let f = s.parse::<f64>().change_context(ParsingFailed)?;
        f.try_into()
    }
}

impl ops::Mul<FiniteAmount> for f64 {
    type Output = f64;

    fn mul(self, rhs: FiniteAmount) -> Self::Output {
        self * rhs.0
    }
}

impl ops::Mul<f64> for FiniteAmount {
    type Output = f64;

    fn mul(self, rhs: f64) -> Self::Output {
        self.0 * rhs
    }
}

impl Display for FiniteAmount {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Denom(cosmrs::Denom);

impl TryFrom<cosmrs::Denom> for Denom {
    type Error = Report<Error>;

    fn try_from(denom: cosmrs::Denom) -> std::result::Result<Self, Self::Error> {
        ensure!(!denom.as_ref().is_empty(), DenomIsEmpty);
        Ok(Denom(denom))
    }
}

impl FromStr for Denom {
    type Err = Report<Error>;

    fn from_str(denom: &str) -> std::result::Result<Self, Self::Err> {
        let denom: cosmrs::Denom = ResultCompatExt::change_context(denom.parse(), ParsingFailed)?;
        denom.try_into()
    }
}

impl From<Denom> for cosmrs::Denom {
    fn from(denom: Denom) -> Self {
        denom.0
    }
}

impl Display for Denom {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use cosmrs::proto;

    use super::DecCoin;

    #[test]
    fn correct_parse() {
        assert!(DecCoin::new(1000.00, "uaxl").is_ok())
    }

    #[test]
    fn failed_amount() {
        assert!(DecCoin::new(f64::NAN, "uaxl").is_err())
    }

    #[test]
    fn empty_denom() {
        assert!(DecCoin::new(1000.00, "").is_err())
    }

    #[test]
    fn invalid_denom() {
        assert!(DecCoin::new(1000.00, "ax~7").is_err())
    }

    #[test]
    fn correct_try_from_string() {
        assert_eq!(
            DecCoin::new(100.0, "uaxl").ok(),
            DecCoin::try_from("100uaxl").ok()
        );
        assert_eq!(
            DecCoin::new(100.5, "uaxl").ok(),
            DecCoin::try_from("100.5uaxl").ok()
        );
        assert_eq!(
            DecCoin::new(100.523478623, "uaxl").ok(),
            DecCoin::try_from("100.523478623uaxl").ok()
        );
        assert_eq!(
            DecCoin::new(10.0, "a0uaxl").ok(),
            DecCoin::try_from("10a0uaxl").ok()
        );
        assert_eq!(
            DecCoin::new(10.0, "a0u/axl").ok(),
            DecCoin::try_from("10a0u/axl").ok()
        );
    }

    #[test]
    fn invalid_try_from_string() {
        assert!(DecCoin::try_from("10a0u/-xl").is_err());
        assert!(DecCoin::try_from("uaxl6").is_err());
    }

    #[test]
    fn map_dec_coin_correct() {
        let coin = proto::cosmos::base::v1beta1::DecCoin {
            denom: "uaxl".to_string(),
            amount: "1000.00".to_string(),
        };
        assert!(DecCoin::try_from(coin).is_ok())
    }

    #[test]
    fn map_dec_coin_invalid_denom() {
        let coin = proto::cosmos::base::v1beta1::DecCoin {
            denom: "".to_string(),
            amount: "1000.00".to_string(),
        };
        assert!(DecCoin::try_from(coin).is_err())
    }

    #[test]
    fn map_dec_coin_invalid_amount() {
        let coin = proto::cosmos::base::v1beta1::DecCoin {
            denom: "uaxl".to_string(),
            amount: "NaN".to_string(),
        };
        assert!(DecCoin::try_from(coin).is_err())
    }
}
