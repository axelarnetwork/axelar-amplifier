use std::fmt;
use std::str::FromStr;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint256};
use lazy_static::lazy_static;
use multisig::key::PublicKey;
use regex::Regex;
use ripemd::Ripemd160;
use router_api::FIELD_DELIMITER;
use sha2::{Digest, Sha256, Sha512};
use sha3::Keccak256;

use crate::error::XRPLError;

const XRPL_PAYMENT_DROPS_HASH_PREFIX: &[u8] = b"xrpl-payment-drops";
const XRPL_PAYMENT_ISSUED_HASH_PREFIX: &[u8] = b"xrpl-payment-issued";

const XRPL_ACCOUNT_ID_LENGTH: usize = 20;
const XRPL_CURRENCY_LENGTH: usize = 20;

pub const XRP_DECIMALS: u8 = 6;
pub const XRPL_ISSUED_TOKEN_DECIMALS: u8 = 15;
pub const XRP_MAX_UINT: u64 = 100_000_000_000_000_000u64;

// https://xrpl.org/docs/references/protocol/data-types/basic-data-types#hash-prefixes
const UNSIGNED_TRANSACTION_MULTI_SIGNING_HASH_PREFIX: [u8; 4] = [0x53, 0x4D, 0x54, 0x00];

lazy_static! {
    static ref CURRENCY_CODE_REGEX: Regex =
        Regex::new(r"^[A-Za-z0-9\?\!@#\$%\^&\*<>\(\)\{\}\[\]\|]{3}$").unwrap();
}

const MIN_MANTISSA: u64 = 1_000_000_000_000_000;
const MAX_MANTISSA: u64 = 10_000_000_000_000_000 - 1;
const MIN_EXPONENT: i64 = -96;
const MAX_EXPONENT: i64 = 80;

pub const XRPL_TOKEN_MIN_MANTISSA: u64 = MIN_MANTISSA;
pub const XRPL_TOKEN_MAX_MANTISSA: u64 = MAX_MANTISSA;
pub const XRPL_TOKEN_MIN_EXPONENT: i64 = MIN_EXPONENT;
pub const XRPL_TOKEN_MAX_EXPONENT: i64 = MAX_EXPONENT;

const MAX_XRPL_TOKEN_AMOUNT: XRPLTokenAmount = XRPLTokenAmount {
    mantissa: MAX_MANTISSA,
    exponent: MAX_EXPONENT,
};

#[cw_serde]
#[derive(Eq, Hash)]
pub struct XRPLToken {
    #[serde(with = "xrpl_account_id_string")]
    #[schemars(with = "String")]
    pub issuer: XRPLAccountId,
    #[serde(with = "xrpl_currency_string")]
    #[schemars(with = "String")]
    pub currency: XRPLCurrency,
}

impl XRPLToken {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(40);
        bytes.extend_from_slice(self.issuer.as_ref());
        bytes.extend_from_slice(self.currency.as_ref());
        bytes
    }
}

impl fmt::Display for XRPLToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.currency, self.issuer)
    }
}

#[cw_serde]
#[derive(Eq, Hash)]
pub enum XRPLPaymentAmount {
    Drops(u64),
    Issued(
        XRPLToken,
        #[serde(with = "xrpl_token_amount_string")]
        #[schemars(with = "String")]
        XRPLTokenAmount,
    ),
}

impl PartialOrd for XRPLPaymentAmount {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match (self, other) {
            (XRPLPaymentAmount::Drops(a), XRPLPaymentAmount::Drops(b)) => a.partial_cmp(b),
            (
                XRPLPaymentAmount::Issued(token_a, amount_a),
                XRPLPaymentAmount::Issued(token_b, amount_b),
            ) => {
                if token_a == token_b {
                    amount_a.partial_cmp(amount_b)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

impl XRPLPaymentAmount {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        let delimiter_bytes = &[FIELD_DELIMITER as u8];

        match self {
            XRPLPaymentAmount::Drops(drops) => {
                hasher.update(XRPL_PAYMENT_DROPS_HASH_PREFIX);
                hasher.update(delimiter_bytes);
                hasher.update(drops.to_be_bytes());
            }
            XRPLPaymentAmount::Issued(token, amount) => {
                hasher.update(XRPL_PAYMENT_ISSUED_HASH_PREFIX);
                hasher.update(delimiter_bytes);
                hasher.update(token.issuer.as_ref());
                hasher.update(delimiter_bytes);
                hasher.update(token.currency.as_ref());
                hasher.update(delimiter_bytes);
                hasher.update(amount.mantissa.to_be_bytes());
                hasher.update(delimiter_bytes);
                hasher.update(amount.exponent.to_be_bytes());
            }
        }

        hasher.finalize().into()
    }

    pub fn zeroize(&self) -> Self {
        match self {
            XRPLPaymentAmount::Drops(_) => XRPLPaymentAmount::Drops(0),
            XRPLPaymentAmount::Issued(token, _) => {
                XRPLPaymentAmount::Issued(token.clone(), XRPLTokenAmount::ZERO)
            }
        }
    }

    pub fn is_zero(&self) -> bool {
        match self {
            &XRPLPaymentAmount::Drops(drops) => drops == 0,
            XRPLPaymentAmount::Issued(_, amount) => amount.is_zero(),
        }
    }
}

impl fmt::Display for XRPLPaymentAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            XRPLPaymentAmount::Drops(drops) => write!(f, "Drops({})", drops),
            XRPLPaymentAmount::Issued(token, amount) => {
                write!(f, "TokenAmount({:?},{:?})", token, amount)
            }
        }
    }
}

#[cw_serde]
#[derive(Eq, Hash)]
pub struct XRPLAccountId([u8; XRPL_ACCOUNT_ID_LENGTH]);

impl XRPLAccountId {
    pub const fn as_bytes(&self) -> [u8; XRPL_ACCOUNT_ID_LENGTH] {
        self.0
    }

    pub fn new(bytes: [u8; XRPL_ACCOUNT_ID_LENGTH]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8; XRPL_ACCOUNT_ID_LENGTH]> for XRPLAccountId {
    fn as_ref(&self) -> &[u8; XRPL_ACCOUNT_ID_LENGTH] {
        &self.0
    }
}

impl From<[u8; XRPL_ACCOUNT_ID_LENGTH]> for XRPLAccountId {
    fn from(bytes: [u8; XRPL_ACCOUNT_ID_LENGTH]) -> Self {
        XRPLAccountId(bytes)
    }
}

impl fmt::Display for XRPLAccountId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut payload = Vec::<u8>::with_capacity(25);
        payload.extend(&[0x00]);
        payload.extend_from_slice(self.as_ref());

        let checksum_hash1 = Sha256::digest(payload.clone());
        let checksum_hash2 = Sha256::digest(checksum_hash1);
        let checksum = &checksum_hash2[0..4];

        payload.extend(checksum);

        let str = bs58::encode(payload)
            .with_alphabet(bs58::Alphabet::RIPPLE)
            .into_string();

        write!(f, "{}", str)
    }
}

impl TryFrom<String> for XRPLAccountId {
    type Error = XRPLError;

    fn try_from(address: String) -> Result<Self, XRPLError> {
        XRPLAccountId::from_str(address.as_str())
    }
}

impl std::str::FromStr for XRPLAccountId {
    type Err = XRPLError;

    fn from_str(address: &str) -> Result<Self, XRPLError> {
        let res = bs58::decode(address)
            .with_alphabet(bs58::Alphabet::RIPPLE)
            .into_vec()
            .map_err(|_| XRPLError::InvalidAddress(address.to_string()))?;

        if res.len() != 25 {
            return Err(XRPLError::InvalidAddress(address.to_string()));
        }
        let mut buffer = [0u8; XRPL_ACCOUNT_ID_LENGTH];
        buffer.copy_from_slice(&res[1..21]);
        Ok(XRPLAccountId(buffer))
    }
}

impl From<&PublicKey> for XRPLAccountId {
    fn from(pub_key: &PublicKey) -> Self {
        let public_key_hex: HexBinary = pub_key.clone().into();

        assert!(public_key_hex.len() == 33);

        let public_key_inner_hash = Sha256::digest(public_key_hex);
        let account_id = Ripemd160::digest(public_key_inner_hash);

        XRPLAccountId(account_id.into())
    }
}

pub mod xrpl_account_id_string {
    use std::str::FromStr;

    use serde::{Deserialize, Deserializer, Serializer};

    use super::XRPLAccountId;

    pub fn serialize<S>(value: &XRPLAccountId, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<XRPLAccountId, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        XRPLAccountId::from_str(&string).map_err(serde::de::Error::custom)
    }
}

// HASHING LOGIC

fn xrpl_hash(prefix: [u8; 4], tx_blob: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512::new_with_prefix(prefix);
    hasher.update(tx_blob);
    let digest: [u8; 64] = hasher.finalize().into();
    digest[..32].try_into().expect("digest should be 32 bytes")
}

pub fn message_to_sign(
    encoded_unsigned_tx: Vec<u8>,
    signer_address: &XRPLAccountId,
) -> Result<[u8; 32], XRPLError> {
    let mut tx_blob = encoded_unsigned_tx.to_vec();
    tx_blob.extend_from_slice(signer_address.as_ref());
    Ok(xrpl_hash(
        UNSIGNED_TRANSACTION_MULTI_SIGNING_HASH_PREFIX,
        tx_blob.as_slice(),
    ))
}

#[cw_serde]
#[derive(Eq, Hash)]
pub struct XRPLCurrency([u8; XRPL_CURRENCY_LENGTH]);

impl XRPLCurrency {
    pub fn new(s: &str) -> Result<Self, XRPLError> {
        if s == "XRP" || !CURRENCY_CODE_REGEX.is_match(s) {
            return Err(XRPLError::InvalidCurrency);
        }

        let mut buffer = [0u8; XRPL_CURRENCY_LENGTH];
        buffer[12..15].copy_from_slice(s.as_bytes());
        Ok(XRPLCurrency(buffer))
    }

    pub fn as_bytes(&self) -> [u8; XRPL_CURRENCY_LENGTH] {
        self.0
    }
}

impl AsRef<[u8; XRPL_CURRENCY_LENGTH]> for XRPLCurrency {
    fn as_ref(&self) -> &[u8; XRPL_CURRENCY_LENGTH] {
        &self.0
    }
}

impl fmt::Display for XRPLCurrency {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = std::str::from_utf8(&self.0[12..15])
            .expect("Currency code should always be valid UTF-8")
            .to_string();
        write!(f, "{}", str)
    }
}

impl TryFrom<String> for XRPLCurrency {
    type Error = XRPLError;

    fn try_from(s: String) -> Result<Self, XRPLError> {
        XRPLCurrency::new(&s)
    }
}

pub mod xrpl_currency_string {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::XRPLCurrency;

    pub fn serialize<S>(value: &XRPLCurrency, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<XRPLCurrency, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        XRPLCurrency::try_from(string).map_err(serde::de::Error::custom)
    }
}

// XRPLTokenAmount always in canonicalized XRPL mantissa-exponent format,
// such that MIN_MANTISSA <= mantissa <= MAX_MANTISSA (or equal to zero), MIN_EXPONENT <= exponent <= MAX_EXPONENT,
// In XRPL generally it can be decimal and even negative (!) but in our case that doesn't apply.
#[cw_serde]
#[derive(Eq, Hash)]
pub struct XRPLTokenAmount {
    mantissa: u64,
    exponent: i64,
}

impl fmt::Display for XRPLTokenAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}e{}", self.mantissa, self.exponent)
    }
}

impl XRPLTokenAmount {
    pub const MAX: XRPLTokenAmount = MAX_XRPL_TOKEN_AMOUNT;

    pub const ZERO: XRPLTokenAmount = XRPLTokenAmount {
        mantissa: 0,
        exponent: 0,
    };

    pub fn new(mantissa: u64, exponent: i64) -> Self {
        assert!(
            mantissa == 0
                || ((MIN_MANTISSA..=MAX_MANTISSA).contains(&mantissa)
                    && (MIN_EXPONENT..=MAX_EXPONENT).contains(&exponent))
        );
        Self { mantissa, exponent }
    }

    pub fn is_zero(&self) -> bool {
        self.mantissa == 0
    }
}

impl PartialOrd for XRPLTokenAmount {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // If either amount is zero, we can compare directly
        if self.mantissa == 0 {
            return if other.mantissa == 0 {
                Some(std::cmp::Ordering::Equal)
            } else {
                Some(std::cmp::Ordering::Less)
            };
        }
        if other.mantissa == 0 {
            return Some(std::cmp::Ordering::Greater);
        }

        // Need to adjust mantissas to compare with same exponent
        let exp_diff = self.exponent - other.exponent;
        if exp_diff == 0 {
            // Same exponent, compare mantissas directly
            return Some(self.mantissa.cmp(&other.mantissa));
        }

        // Need to adjust mantissas to compare with same exponent
        let (adjusted_mantissa, adjusted_other_mantissa) = if exp_diff > 0 {
            // self has larger exponent (e.g., 15e2 vs 150e1)
            // Multiply other's mantissa by 10^exp_diff to normalize
            match other.mantissa.checked_mul(10u64.pow(exp_diff as u32)) {
                Some(adjusted) => (self.mantissa, adjusted),
                None => {
                    // If multiplication would overflow, self must be larger
                    // This happens when the difference in exponents is so large
                    // that adjusting would exceed u64::MAX
                    return Some(std::cmp::Ordering::Greater);
                }
            }
        } else {
            // other has larger exponent (e.g., 150e1 vs 15e2)
            // Multiply self's mantissa by 10^(-exp_diff) to normalize
            match self.mantissa.checked_mul(10u64.pow((-exp_diff) as u32)) {
                Some(adjusted) => (adjusted, other.mantissa),
                None => {
                    // Multiplication would overflow, so other must be larger
                    return Some(std::cmp::Ordering::Less);
                }
            }
        };

        Some(adjusted_mantissa.cmp(&adjusted_other_mantissa))
    }
}

impl std::str::FromStr for XRPLTokenAmount {
    type Err = XRPLError;

    fn from_str(s: &str) -> Result<Self, XRPLError> {
        let exp_separator: &[_] = &['e', 'E'];

        let (base_part, exponent_value) = match s.find(exp_separator) {
            None => (s, 0),
            Some(loc) => {
                let (base, exp) = (
                    &s[..loc],
                    &s[loc.checked_add(1).ok_or(XRPLError::InvalidAmount {
                        reason: "exponent out of bounds".to_string(),
                    })?..],
                );
                (
                    base,
                    i64::from_str(exp).map_err(|_| XRPLError::InvalidAmount {
                        reason: "invalid exponent".to_string(),
                    })?,
                )
            }
        };

        if base_part.is_empty() {
            return Err(XRPLError::InvalidAmount {
                reason: "base part empty".to_string(),
            });
        }

        let (mut digits, decimal_offset): (String, _) = match base_part.find('.') {
            None => (base_part.to_string(), 0),
            Some(loc) => {
                let (lead, trail) = (
                    &base_part[..loc],
                    &base_part[loc.checked_add(1).ok_or(XRPLError::InvalidAmount {
                        reason: "decimal point out of bounds".to_string(),
                    })?..],
                );
                let mut digits = String::from(lead);
                digits.push_str(trail);
                let trail_digits = trail.chars().filter(|c| *c != '_').count();
                (digits, trail_digits as i64)
            }
        };

        let exponent = match exponent_value.checked_sub(decimal_offset) {
            Some(exponent) => exponent,
            None => {
                return Err(XRPLError::InvalidAmount {
                    reason: "overflow".to_string(),
                });
            }
        };

        if digits.starts_with('-') {
            return Err(XRPLError::InvalidAmount {
                reason: "negative amount".to_string(),
            });
        }

        if digits.starts_with('+') {
            digits = digits[1..].to_string();
        }

        let mantissa =
            Uint256::from_str(digits.as_str()).map_err(|e| XRPLError::InvalidAmount {
                reason: e.to_string(),
            })?;

        let (mantissa, exponent) = canonicalize_mantissa(mantissa, exponent)?;

        Ok(XRPLTokenAmount::new(mantissa, exponent))
    }
}

impl TryFrom<String> for XRPLTokenAmount {
    type Error = XRPLError;

    fn try_from(s: String) -> Result<Self, XRPLError> {
        XRPLTokenAmount::from_str(s.as_str())
    }
}

mod xrpl_token_amount_string {
    use std::str::FromStr;

    use serde::{Deserialize, Deserializer, Serializer};

    use super::XRPLTokenAmount;

    pub fn serialize<S>(value: &XRPLTokenAmount, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<XRPLTokenAmount, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        XRPLTokenAmount::from_str(&string).map_err(serde::de::Error::custom)
    }
}

// always called when XRPLTokenAmount instantiated
// see https://github.com/XRPLF/xrpl-dev-portal/blob/82da0e53a8d6cdf2b94a80594541d868b4d03b94/content/_code-samples/tx-serialization/py/xrpl_num.py#L19
pub fn canonicalize_mantissa(
    mut mantissa: Uint256,
    mut exponent: i64,
) -> Result<(u64, i64), XRPLError> {
    let ten = Uint256::from(10u128);

    while mantissa < MIN_MANTISSA.into() && exponent > MIN_EXPONENT {
        mantissa = mantissa
            .checked_mul(ten)
            .map_err(|_| XRPLError::InvalidAmount {
                reason: "multiplication overflow".to_string(),
            })?;
        exponent = exponent.checked_sub(1).ok_or(XRPLError::InvalidAmount {
            reason: "exponent underflow".to_string(),
        })?;
    }

    while mantissa > MAX_MANTISSA.into() && exponent > MIN_EXPONENT {
        if exponent >= MAX_EXPONENT {
            return Err(XRPLError::InvalidAmount {
                reason: "overflow".to_string(),
            });
        }
        mantissa = mantissa
            .checked_div(ten)
            .map_err(|_| XRPLError::InvalidAmount {
                reason: "division overflow".to_string(),
            })?;
        exponent = exponent.checked_add(1).ok_or(XRPLError::InvalidAmount {
            reason: "exponent overflow".to_string(),
        })?;
    }

    if exponent < MIN_EXPONENT || mantissa < MIN_MANTISSA.into() {
        return Ok((0, 1));
    }

    if exponent > MAX_EXPONENT || mantissa > MAX_MANTISSA.into() {
        return Err(XRPLError::InvalidAmount {
            reason: format!("overflow exponent {} mantissa {}", exponent, mantissa).to_string(),
        });
    }

    let mantissa = u64::from_be_bytes(
        mantissa.to_be_bytes()[24..32]
            .try_into()
            .expect("mantissa should be 8 bytes"),
    );

    Ok((mantissa, exponent))
}

pub fn scale_to_decimals(
    amount: XRPLTokenAmount,
    destination_decimals: u8,
) -> Result<(Uint256, XRPLTokenAmount), XRPLError> {
    if amount.mantissa == 0 {
        return Ok((Uint256::zero(), amount));
    }

    let mantissa = Uint256::from(amount.mantissa);
    let ten = Uint256::from(10u64);

    let adjusted_exponent = amount
        .exponent
        .checked_add(i64::from(destination_decimals))
        .ok_or(XRPLError::Overflow)?;
    if adjusted_exponent >= 0 {
        Ok((
            mantissa
                .checked_mul(
                    ten.checked_pow(
                        adjusted_exponent
                            .try_into()
                            .expect("adjusted exponent should be positive and within u32 range"),
                    )
                    .map_err(|_| XRPLError::Overflow)?,
                )
                .map_err(|_| XRPLError::Overflow)?,
            XRPLTokenAmount::ZERO,
        ))
    } else {
        Ok(ten
            .checked_pow(
                adjusted_exponent
                    .checked_neg()
                    .expect("adjusted_exponent should be negative")
                    .try_into()
                    .expect("exponent should be negative and within u32 range"),
            )
            .map(|scaling_factor| {
                let quotient = mantissa
                    .checked_div(scaling_factor)
                    .expect("mantissa should be divisible by 10^(-exponent)");
                let dust_amount = mantissa
                    .checked_sub(
                        quotient
                            .checked_mul(scaling_factor)
                            .expect("scaling factor must be non-zero"),
                    )
                    .expect("subtraction must not overflow");
                (
                    quotient,
                    if dust_amount == Uint256::zero() {
                        XRPLTokenAmount::ZERO
                    } else {
                        let (dust_mantissa, dust_exponent) =
                            canonicalize_mantissa(dust_amount, amount.exponent)
                                .expect("dust amount should be canonicalizable");
                        XRPLTokenAmount::new(dust_mantissa, dust_exponent)
                    },
                )
            })
            .unwrap_or((Uint256::zero(), amount)))
    }
}

fn convert_scaled_uint256_to_u64(value: Uint256) -> u64 {
    let mut last_8 = [0u8; 8];
    last_8.copy_from_slice(&value.to_be_bytes()[24..32]);
    u64::from_be_bytes(last_8)
}

fn convert_scaled_uint256_to_drops(value: Uint256) -> Result<u64, XRPLError> {
    if value.gt(&XRP_MAX_UINT.into()) {
        return Err(XRPLError::Overflow);
    }

    Ok(convert_scaled_uint256_to_u64(value))
}

// Converts XRP drops to the destination chain's token amount.
pub fn scale_from_drops(drops: u64, destination_decimals: u8) -> Result<(Uint256, u64), XRPLError> {
    if drops > XRP_MAX_UINT {
        return Err(XRPLError::InvalidDrops(drops));
    }

    if destination_decimals > 82 {
        return Err(XRPLError::InvalidDecimals(destination_decimals));
    }

    let source_amount = Uint256::from(drops);
    if XRP_DECIMALS == destination_decimals {
        return Ok((source_amount, 0u64));
    }

    let scaling_factor = Uint256::from(10u8)
        .checked_pow(XRP_DECIMALS.abs_diff(destination_decimals).into())
        .expect("exponent cannot be too large");

    let (destination_amount, dust_amount) = if XRP_DECIMALS > destination_decimals {
        let quotient = source_amount
            .checked_div(scaling_factor)
            .expect("scaling factor must be non-zero");
        (
            quotient,
            convert_scaled_uint256_to_u64(
                source_amount
                    .checked_sub(
                        quotient
                            .checked_mul(scaling_factor)
                            .expect("scaling factor must be non-zero"),
                    )
                    .expect("subtraction must not overflow"),
            ),
        )
    } else {
        (
            source_amount
                .checked_mul(scaling_factor)
                .expect("multiplication should not overflow"),
            0u64,
        )
    };

    Ok((destination_amount, dust_amount))
}

// Converts the given amount of tokens to XRP drops.
pub fn scale_to_drops(
    source_amount: Uint256,
    source_decimals: u8,
) -> Result<(u64, Uint256), XRPLError> {
    if source_amount.is_zero() {
        return Ok((0, Uint256::zero()));
    }

    if source_decimals > 82 {
        return Err(XRPLError::InvalidDecimals(source_decimals));
    }

    if source_decimals == XRP_DECIMALS {
        return Ok((
            convert_scaled_uint256_to_drops(source_amount)?,
            Uint256::zero(),
        ));
    }

    let scaling_factor = Uint256::from(10u8)
        .checked_pow(source_decimals.abs_diff(XRP_DECIMALS).into())
        .expect("exponent cannot be too large");

    let (destination_amount, dust) = if source_decimals > XRP_DECIMALS {
        let quotient = source_amount
            .checked_div(scaling_factor)
            .expect("scaling factor must be non-zero");
        (
            quotient,
            source_amount
                .checked_sub(
                    quotient
                        .checked_mul(scaling_factor)
                        .expect("scaling factor must be non-zero"),
                )
                .expect("subtraction must not overflow"),
        )
    } else {
        (
            source_amount
                .checked_mul(scaling_factor)
                .map_err(|_| XRPLError::Overflow)?,
            Uint256::zero(),
        )
    };

    Ok((convert_scaled_uint256_to_drops(destination_amount)?, dust))
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::Uint256;

    use super::*;

    #[test]
    fn test_account_id_to_bytes() {
        assert_eq!(
            "rrrrrrrrrrrrrrrrrrrrrhoLvTp",
            XRPLAccountId::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
                .to_string()
        );
        assert_eq!(
            "rQLbzfJH5BT1FS9apRLKV3G8dWEA5njaQi",
            XRPLAccountId::from([
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255
            ])
            .to_string()
        );
    }

    #[test]
    fn test_ed25519_public_key_to_xrpl_address() -> Result<(), XRPLError> {
        assert_eq!(
            XRPLAccountId::from(&PublicKey::Ed25519(HexBinary::from_hex(
                "ED9434799226374926EDA3B54B1B461B4ABF7237962EAE18528FEA67595397FA32"
            )?))
            .to_string(),
            "rDTXLQ7ZKZVKz33zJbHjgVShjsBnqMBhmN"
        );
        Ok(())
    }

    #[test]
    fn test_secp256k1_public_key_to_xrpl_address() -> Result<(), XRPLError> {
        assert_eq!(
            XRPLAccountId::from(&PublicKey::Ecdsa(HexBinary::from_hex(
                "0303E20EC6B4A39A629815AE02C0A1393B9225E3B890CAE45B59F42FA29BE9668D"
            )?))
            .to_string(),
            "rnBFvgZphmN39GWzUJeUitaP22Fr9be75H"
        );
        Ok(())
    }

    #[test]
    fn test_scale_to_decimals() {
        let amount = XRPLTokenAmount::new(1_000_000_000_000_000u64, -33);
        assert_eq!(
            scale_to_decimals(amount, 18).unwrap(),
            (Uint256::one(), XRPLTokenAmount::ZERO)
        );

        let amount = XRPLTokenAmount::new(1_000_000_000_000_000u64, -15);
        assert_eq!(
            scale_to_decimals(amount, 18).unwrap(),
            (
                Uint256::from(1_000_000_000_000_000_000u64),
                XRPLTokenAmount::ZERO
            )
        );

        let amount = XRPLTokenAmount::new(1_234_567_891_234_567u64, -15);
        assert_eq!(
            scale_to_decimals(amount, 18).unwrap(),
            (
                Uint256::from(1_234_567_891_234_567_000u64),
                XRPLTokenAmount::ZERO
            )
        );

        let amount = XRPLTokenAmount::new(1_234_567_891_234_567u64, -15);
        assert_eq!(
            scale_to_decimals(amount, 6).unwrap(),
            (
                Uint256::from(1_234_567u64),
                XRPLTokenAmount::new(8_912_345_670_000_000u64, -22)
            )
        );

        let amount = XRPLTokenAmount::new(9_999_999_999_999_999u64, 55);
        assert_eq!(
            scale_to_decimals(amount, 6).unwrap(),
            (
                Uint256::try_from(
                    "99999999999999990000000000000000000000000000000000000000000000000000000000000"
                )
                .unwrap(),
                XRPLTokenAmount::ZERO
            )
        );

        let amount = XRPLTokenAmount::new(9_999_999_999_999_999u64, 56);
        let result = scale_to_decimals(amount, 6);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "overflow");
    }

    #[test]
    fn test_large_exponent_handling() {
        let amount = XRPLTokenAmount::new(9_999_999_999_999_999u64, 70);
        let result = scale_to_decimals(amount, 18);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "overflow");
    }

    #[test]
    fn test_large_mantissa_handling() {
        let amount = XRPLTokenAmount::new(9_999_999_999_999_999u64, 0);
        let result = scale_to_decimals(amount, 18);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            (
                Uint256::from(9999999999999999000000000000000000u128),
                XRPLTokenAmount::ZERO
            )
        );
    }

    #[test]
    fn test_small_mantissa_handling() {
        let amount = XRPLTokenAmount::new(9_999_999_999_999_999u64, MIN_EXPONENT);
        let result = scale_to_decimals(amount, 18);
        assert_eq!(
            result.unwrap(),
            (
                Uint256::zero(),
                XRPLTokenAmount::new(9_999_999_999_999_999u64, MIN_EXPONENT)
            )
        );
    }

    #[test]
    fn test_extreme_scaling_down() {
        let amount = XRPLTokenAmount::new(MAX_MANTISSA, MIN_EXPONENT);
        let result = scale_to_decimals(amount, 6);
        assert_eq!(
            result.unwrap(),
            (
                Uint256::zero(),
                XRPLTokenAmount::new(MAX_MANTISSA, MIN_EXPONENT)
            )
        );
    }

    #[test]
    fn test_extreme_scaling_up() {
        let amount = XRPLTokenAmount::new(MIN_MANTISSA, MAX_EXPONENT);
        let result = scale_to_decimals(amount, 18);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "overflow");
    }

    #[test]
    fn test_scale_from_drops() {
        assert_eq!(
            scale_from_drops(1_000_000, 18).unwrap(),
            (Uint256::from(1_000_000_000_000_000_000u64), 0u64)
        );
        assert_eq!(
            scale_from_drops(100000000000000000, 18).unwrap(),
            (Uint256::from(100000000000000000000000000000u128), 0u64)
        );
        assert_eq!(
            scale_from_drops(1_000_000, 6).unwrap(),
            (Uint256::from(1_000_000u32), 0u64)
        );
        assert_eq!(
            scale_from_drops(1_234_567, 18).unwrap(),
            (Uint256::from(1_234_567_000_000_000_000u64), 0u64)
        );
        assert_eq!(
            scale_from_drops(1_000_000, 6).unwrap(),
            (Uint256::from(1_000_000u32), 0u64)
        );
        assert_eq!(
            scale_from_drops(1_000_001, 5).unwrap(),
            (Uint256::from(100_000u32), 1u64)
        );
        assert_eq!(
            scale_from_drops(1_000_123, 3).unwrap(),
            (Uint256::from(1_000u32), 123u64)
        );
        assert_eq!(
            scale_from_drops(1_123_456_789, 3).unwrap(),
            (Uint256::from(1_123_456u32), 789u64)
        );
        assert_eq!(
            scale_from_drops(1_123_456_789, 1).unwrap(),
            (Uint256::from(11_234u32), 56_789u64)
        );
        assert_eq!(scale_from_drops(1, 5).unwrap(), (Uint256::zero(), 1u64));
    }

    #[test]
    fn test_scale_from_invalid_drops() {
        let result = scale_from_drops(XRP_MAX_UINT + 1, 18);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "invalid drops 100000000000000001"
        );
    }

    #[test]
    fn test_xrpl_account_id_from_string() {
        let xrpl_account = "rNM8ue6DZpneFC4gBEJMSEdbwNEBZjs3Dy";
        let expected_bytes: &[u8; XRPL_ACCOUNT_ID_LENGTH] = &[
            146, 136, 70, 186, 245, 155, 212, 140, 40, 177, 49, 133, 84, 114, 208, 76, 147, 187,
            208, 183,
        ];
        assert_eq!(
            XRPLAccountId::from_str(xrpl_account).unwrap().as_ref(),
            expected_bytes
        );
    }

    #[test]
    fn test_token_amount_comparison() {
        let a1 = XRPLTokenAmount::new(1_500_000_000_000_000, -15); // 1.5
        let a2 = XRPLTokenAmount::new(1_500_000_000_000_000, -15); // 1.5
        assert_eq!(a1.partial_cmp(&a2), Some(std::cmp::Ordering::Equal));

        let b1 = XRPLTokenAmount::new(1_500_000_000_000_000, -15); // 1.5
        let b2 = XRPLTokenAmount::new(2_500_000_000_000_000, -15); // 2.5
        assert_eq!(b1.partial_cmp(&b2), Some(std::cmp::Ordering::Less));

        let c1 = XRPLTokenAmount::new(1_500_000_000_000_000, -13); // 150
        let c2 = XRPLTokenAmount::new(2_500_000_000_000_000, -15); // 2.5
        assert_eq!(c1.partial_cmp(&c2), Some(std::cmp::Ordering::Greater));

        let e1 = XRPLTokenAmount::ZERO;
        let e2 = XRPLTokenAmount::new(1_500_000_000_000_000, -15);
        assert_eq!(e1.partial_cmp(&e2), Some(std::cmp::Ordering::Less));
        assert_eq!(e2.partial_cmp(&e1), Some(std::cmp::Ordering::Greater));
    }
}
