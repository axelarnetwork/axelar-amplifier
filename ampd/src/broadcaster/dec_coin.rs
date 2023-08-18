use std::convert::{TryFrom, TryInto};
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;
use std::{fmt, ops};

use cosmrs::proto;
use error_stack::{ensure, IntoReport, IntoReportCompat, Report, Result, ResultExt};
use serde::{Deserialize, Serialize};
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, PartialOrd)]
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
        let f = s.parse::<f64>().into_report().change_context(ParsingFailed)?;
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
        let denom: cosmrs::Denom = IntoReportCompat::into_report(denom.parse()).change_context(ParsingFailed)?;
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
    use super::DecCoin;
    use cosmrs::proto;
    use std::convert::TryFrom;

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
