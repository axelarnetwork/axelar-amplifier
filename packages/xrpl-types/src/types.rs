use std::cmp::min;
use std::fmt;
use std::ops::{Add, Sub};
use std::str::FromStr;

use axelar_wasm_std::msg_id::HexTxHash;
use axelar_wasm_std::{nonempty, Participant, VerificationStatus};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, HexBinary, StdError, StdResult, Uint256};
use cw_storage_plus::{Key, KeyDeserialize, PrimaryKey};
use k256::ecdsa;
use k256::schnorr::signature::SignatureEncoding;
use lazy_static::lazy_static;
use multisig::PublicKey;
use regex::Regex;
use ripemd::Ripemd160;
use router_api::{CrossChainId, FIELD_DELIMITER};
use sha2::{Digest, Sha256, Sha512};
use sha3::Keccak256;

use crate::error::XRPLError;

const XRPL_PAYMENT_DROPS_HASH_PREFIX: &[u8] = b"xrpl-payment-drops";
const XRPL_PAYMENT_ISSUED_HASH_PREFIX: &[u8] = b"xrpl-payment-issued";

const XRPL_ACCOUNT_ID_LENGTH: usize = 20;
const XRPL_CURRENCY_LENGTH: usize = 20;

const XRP_RESERVED_CURRENCY: [u8; XRPL_CURRENCY_LENGTH] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, b'X', b'R', b'P', 0, 0, 0, 0, 0,
];
const ZERO_RESERVED_CURRENCY: [u8; XRPL_CURRENCY_LENGTH] = [0; XRPL_CURRENCY_LENGTH];

pub const XRP_DECIMALS: u8 = 6;
pub const XRPL_ISSUED_TOKEN_DECIMALS: u8 = 15;
pub const XRP_MAX_UINT: u64 = 100_000_000_000_000_000u64;

const SIGNED_TRANSACTION_HASH_PREFIX: [u8; 4] = [0x54, 0x58, 0x4E, 0x00];
// https://xrpl.org/docs/references/protocol/data-types/basic-data-types#hash-prefixes
const UNSIGNED_TRANSACTION_MULTI_SIGNING_HASH_PREFIX: [u8; 4] = [0x53, 0x4D, 0x54, 0x00];

lazy_static! {
    static ref STANDARD_CURRENCY_CODE_REGEX: Regex =
        Regex::new(r"^[A-Za-z0-9\?\!@#\$%\^&\*<>\(\)\{\}\[\]\|]{3}$").expect("valid regex");
    static ref NON_STANDARD_CURRENCY_CODE_REGEX: Regex =
        Regex::new(r"^[A-Fa-f0-9]{40}$").expect("valid regex");
}

// https://xrpl.org/docs/references/protocol/binary-format#token-amount-format
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
#[derive(Eq, Ord, PartialOrd)]
pub struct AxelarSigner {
    pub address: Addr,
    pub weight: u16,
    pub pub_key: PublicKey,
}

impl TryFrom<AxelarSigner> for Participant {
    type Error = XRPLError;
    fn try_from(signer: AxelarSigner) -> Result<Self, XRPLError> {
        let weight = nonempty::Uint128::try_from(u128::from(signer.weight))
            .map_err(|_| XRPLError::InvalidSignerWeight(signer.weight))?;

        Ok(Self {
            address: signer.address,
            weight,
        })
    }
}

#[cw_serde]
pub enum XRPLTxStatus {
    Pending,
    Succeeded,
    FailedOnChain,
    Inconclusive,
}

impl fmt::Display for XRPLTxStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            XRPLTxStatus::Pending => write!(f, "Pending"),
            XRPLTxStatus::Succeeded => write!(f, "Succeeded"),
            XRPLTxStatus::FailedOnChain => write!(f, "FailedOnChain"),
            XRPLTxStatus::Inconclusive => write!(f, "Inconclusive"),
        }
    }
}

impl From<VerificationStatus> for XRPLTxStatus {
    fn from(val: VerificationStatus) -> Self {
        match val {
            VerificationStatus::SucceededOnSourceChain => XRPLTxStatus::Succeeded, // message was found and its execution was successful
            VerificationStatus::FailedOnSourceChain => XRPLTxStatus::FailedOnChain, // message was found but its execution failed
            VerificationStatus::NotFoundOnSourceChain // message was not found on source chain
            | VerificationStatus::FailedToVerify // verification process failed, e.g. no consensus reached
            | VerificationStatus::InProgress // verification in progress
            | VerificationStatus::Unknown // not verified yet, i.e. has never been part of a poll
            => XRPLTxStatus::Inconclusive,
        }
    }
}

#[cw_serde]
pub struct TxInfo {
    pub status: XRPLTxStatus,
    pub unsigned_contents: XRPLUnsignedTx,
    pub original_cc_id: Option<CrossChainId>,
}

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
        let mut bytes = Vec::with_capacity(XRPL_ACCOUNT_ID_LENGTH + XRPL_CURRENCY_LENGTH);
        bytes.extend_from_slice(self.issuer.as_ref());
        bytes.extend_from_slice(self.currency.as_ref());
        bytes
    }

    pub fn is_local(&self, xrpl_multisig: XRPLAccountId) -> bool {
        self.issuer != xrpl_multisig
    }

    pub fn is_remote(&self, xrpl_multisig: XRPLAccountId) -> bool {
        !self.is_local(xrpl_multisig)
    }
}

impl PrimaryKey<'_> for XRPLToken {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = XRPLToken;
    type SuperSuffix = XRPLToken;

    fn key(&self) -> Vec<Key> {
        vec![
            Key::Ref(self.issuer.as_ref()),
            Key::Ref(self.currency.as_ref()),
        ]
    }
}

impl KeyDeserialize for XRPLToken {
    type Output = XRPLToken;
    const KEY_ELEMS: u16 = 2;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        if value.len() != XRPL_ACCOUNT_ID_LENGTH + XRPL_CURRENCY_LENGTH {
            return Err(StdError::generic_err("Invalid key length for XRPLToken"));
        }

        let issuer: [u8; XRPL_ACCOUNT_ID_LENGTH] = value[0..XRPL_ACCOUNT_ID_LENGTH]
            .try_into()
            .map_err(|_| StdError::generic_err("Invalid issuer bytes"))?;

        let currency: [u8; XRPL_CURRENCY_LENGTH] = value
            [XRPL_ACCOUNT_ID_LENGTH..(XRPL_ACCOUNT_ID_LENGTH + XRPL_CURRENCY_LENGTH)]
            .try_into()
            .map_err(|_| StdError::generic_err("Invalid currency bytes"))?;

        Ok(XRPLToken {
            issuer: XRPLAccountId(issuer),
            currency: XRPLCurrency(currency),
        })
    }
}

impl XRPLToken {
    pub fn serialize(&self) -> String {
        format!("{}.{}", self.currency, self.issuer)
    }
}

impl fmt::Display for XRPLToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.serialize())
    }
}

#[cw_serde]
pub enum XRPLTokenOrXrp {
    Xrp,
    Issued(XRPLToken),
}

impl XRPLTokenOrXrp {
    pub fn serialize(&self) -> String {
        match self {
            XRPLTokenOrXrp::Xrp => "XRP".to_string(),
            XRPLTokenOrXrp::Issued(token) => token.serialize(),
        }
    }

    pub fn decimals(&self) -> u8 {
        match self {
            XRPLTokenOrXrp::Xrp => XRP_DECIMALS,
            XRPLTokenOrXrp::Issued(_) => XRPL_ISSUED_TOKEN_DECIMALS,
        }
    }

    pub fn token_address(&self) -> nonempty::HexBinary {
        nonempty::HexBinary::try_from(self.serialize().as_bytes().to_vec())
            .expect("token address should be nonempty")
    }
}

impl fmt::Display for XRPLTokenOrXrp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.serialize())
    }
}

impl XRPLTokenOrXrp {
    pub fn is_local(&self, xrpl_multisig: XRPLAccountId) -> bool {
        match self {
            XRPLTokenOrXrp::Xrp => true,
            XRPLTokenOrXrp::Issued(token) => token.is_local(xrpl_multisig),
        }
    }

    pub fn is_remote(&self, xrpl_multisig: XRPLAccountId) -> bool {
        !self.is_local(xrpl_multisig)
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
            ) if token_a == token_b => amount_a.partial_cmp(amount_b),
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

impl Add for XRPLPaymentAmount {
    type Output = Result<XRPLPaymentAmount, XRPLError>;

    fn add(self, rhs: XRPLPaymentAmount) -> Self::Output {
        match (self, rhs) {
            (XRPLPaymentAmount::Drops(x), XRPLPaymentAmount::Drops(y)) => x
                .checked_add(y)
                .map(XRPLPaymentAmount::Drops)
                .ok_or(XRPLError::AdditionOverflow),
            (
                XRPLPaymentAmount::Issued(token_x, amount_x),
                XRPLPaymentAmount::Issued(token_y, amount_y),
            ) if token_x == token_y => {
                Ok(XRPLPaymentAmount::Issued(token_x, amount_x.add(amount_y)?))
            }
            _ => Err(XRPLError::IncompatibleTokens),
        }
    }
}

impl Sub for XRPLPaymentAmount {
    type Output = Result<XRPLPaymentAmount, XRPLError>;

    fn sub(self, rhs: XRPLPaymentAmount) -> Self::Output {
        match (self, rhs) {
            (XRPLPaymentAmount::Drops(x), XRPLPaymentAmount::Drops(y)) => x
                .checked_sub(y)
                .map(XRPLPaymentAmount::Drops)
                .ok_or(XRPLError::SubtractionUnderflow),
            (
                XRPLPaymentAmount::Issued(token_x, amount_x),
                XRPLPaymentAmount::Issued(token_y, amount_y),
            ) if token_x == token_y => {
                Ok(XRPLPaymentAmount::Issued(token_x, amount_x.sub(amount_y)?))
            }
            _ => Err(XRPLError::IncompatibleTokens),
        }
    }
}

#[cw_serde]
pub struct XRPLMemo {
    pub memo_type: HexBinary,
    pub memo_data: HexBinary,
}

#[cw_serde]
pub enum XRPLSequence {
    Plain(u32),
    Ticket(u32),
}

impl From<&XRPLSequence> for u32 {
    fn from(value: &XRPLSequence) -> Self {
        match *value {
            XRPLSequence::Plain(sequence) => sequence,
            XRPLSequence::Ticket(ticket) => ticket,
        }
    }
}

#[cw_serde]
pub struct XRPLSignerEntry {
    pub account: XRPLAccountId,
    pub signer_weight: u16,
}

impl From<AxelarSigner> for XRPLSignerEntry {
    fn from(signer: AxelarSigner) -> Self {
        Self {
            account: XRPLAccountId::from(&signer.pub_key),
            signer_weight: signer.weight,
        }
    }
}

#[cw_serde]
pub enum XRPLUnsignedTx {
    Payment(XRPLPaymentTx),
    SignerListSet(XRPLSignerListSetTx),
    TicketCreate(XRPLTicketCreateTx),
    TrustSet(XRPLTrustSetTx),
}

#[cw_serde]
pub enum XRPLUnsignedTxType {
    Payment,
    SignerListSet,
    TicketCreate,
    TrustSet,
}

impl XRPLUnsignedTxType {
    pub fn object_count_increment(&self) -> u8 {
        match self {
            // Payments do not increment the object count.
            XRPLUnsignedTxType::Payment => 0,
            // SignerListSet only increments the object count
            // if the signer list is not empty, so on multisig deployment.
            // We consider this 1 object a fixed cost to the reserve.
            // The reserve should always have sufficient XRP to cover that.
            XRPLUnsignedTxType::SignerListSet => 0,
            // Since the target ticket count is always 250 (the max),
            // we consider those 250 objects as a fixed cost to the reserve.
            // The reserve should always have sufficient XRP to cover that.
            // Hence, each TicketCreate does not increment the object count.
            XRPLUnsignedTxType::TicketCreate => 0,
            // Each new trust line increments the object count by 1.
            XRPLUnsignedTxType::TrustSet => 1,
        }
    }
}

#[cw_serde]
pub struct XRPLUnsignedTxToSign {
    pub unsigned_tx: XRPLUnsignedTx,
    pub unsigned_tx_hash: HexTxHash,
    pub cc_id: Option<CrossChainId>,
}

impl XRPLUnsignedTx {
    pub fn fee(&self) -> u64 {
        match self {
            XRPLUnsignedTx::Payment(tx) => tx.fee,
            XRPLUnsignedTx::TicketCreate(tx) => tx.fee,
            XRPLUnsignedTx::SignerListSet(tx) => tx.fee,
            XRPLUnsignedTx::TrustSet(tx) => tx.fee,
        }
    }

    pub fn sequence(&self) -> &XRPLSequence {
        match self {
            XRPLUnsignedTx::Payment(tx) => &tx.sequence,
            XRPLUnsignedTx::TicketCreate(tx) => &tx.sequence,
            XRPLUnsignedTx::SignerListSet(tx) => &tx.sequence,
            XRPLUnsignedTx::TrustSet(tx) => &tx.sequence,
        }
    }

    pub fn is_sequential(&self) -> bool {
        match self.sequence() {
            XRPLSequence::Plain(_) => true,
            XRPLSequence::Ticket(_) => false,
        }
    }

    pub fn sequence_number_increment(&self, status: XRPLTxStatus) -> Result<u32, XRPLError> {
        if status == XRPLTxStatus::Pending || status == XRPLTxStatus::Inconclusive {
            return Ok(0);
        }

        Ok(match self {
            XRPLUnsignedTx::Payment(tx) => match tx.sequence {
                XRPLSequence::Plain(_) => 1,
                XRPLSequence::Ticket(_) => 0,
            },
            XRPLUnsignedTx::SignerListSet(tx) => match tx.sequence {
                XRPLSequence::Plain(_) => 1,
                XRPLSequence::Ticket(_) => 0,
            },
            XRPLUnsignedTx::TicketCreate(tx) => match status {
                XRPLTxStatus::Succeeded => tx
                    .ticket_count
                    .checked_add(1)
                    .ok_or(XRPLError::AdditionOverflow)?,
                XRPLTxStatus::FailedOnChain => 1,
                XRPLTxStatus::Inconclusive | XRPLTxStatus::Pending => unreachable!(),
            },
            XRPLUnsignedTx::TrustSet(tx) => match tx.sequence {
                XRPLSequence::Plain(_) => 1,
                XRPLSequence::Ticket(_) => 0,
            },
        })
    }
}

#[cw_serde]
pub struct XRPLPaymentTx {
    pub account: XRPLAccountId,
    pub fee: u64,
    pub sequence: XRPLSequence,
    pub amount: XRPLPaymentAmount,
    pub destination: XRPLAccountId,
    pub cross_currency: Option<XRPLCrossCurrencyOptions>,
}

#[cw_serde]
pub struct XRPLSignerListSetTx {
    pub account: XRPLAccountId,
    pub fee: u64,
    pub sequence: XRPLSequence,
    pub signer_quorum: u32,
    pub signer_entries: Vec<XRPLSignerEntry>,
}

#[cw_serde]
pub struct XRPLTicketCreateTx {
    pub account: XRPLAccountId,
    pub fee: u64,
    pub sequence: XRPLSequence,
    pub ticket_count: u32,
}

#[cw_serde]
pub struct XRPLTrustSetTx {
    pub token: XRPLToken,
    pub account: XRPLAccountId,
    pub fee: u64,
    pub sequence: XRPLSequence,
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

impl TryFrom<nonempty::HexBinary> for XRPLAccountId {
    type Error = XRPLError;

    fn try_from(hex: nonempty::HexBinary) -> Result<Self, XRPLError> {
        HexBinary::from(hex.as_slice()).try_into()
    }
}

impl TryFrom<HexBinary> for XRPLAccountId {
    type Error = XRPLError;

    fn try_from(hex: HexBinary) -> Result<Self, XRPLError> {
        let bytes: [u8; XRPL_ACCOUNT_ID_LENGTH] = hex
            .as_slice()
            .try_into()
            .map_err(|_| XRPLError::InvalidAddress(hex.to_string()))?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for XRPLAccountId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut payload = Vec::<u8>::with_capacity(25);
        payload.push(0x00);
        payload.extend_from_slice(self.as_ref());

        let checksum_hash1 = Sha256::digest(&payload);
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

impl TryFrom<nonempty::String> for XRPLAccountId {
    type Error = XRPLError;

    fn try_from(address: nonempty::String) -> Result<Self, XRPLError> {
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

#[cw_serde]
pub struct XRPLSigner {
    pub account: XRPLAccountId,
    pub txn_signature: HexBinary,
    pub signing_pub_key: PublicKey,
}

impl TryFrom<multisig::SignerWithSig> for XRPLSigner {
    type Error = XRPLError;

    fn try_from(signer_with_sig: multisig::SignerWithSig) -> Result<Self, XRPLError> {
        let multisig::SignerWithSig { signer, signature } = signer_with_sig;

        let txn_signature = match signer.pub_key {
            multisig::PublicKey::Ecdsa(_) => HexBinary::from(
                ecdsa::Signature::to_der(
                    &ecdsa::Signature::try_from(signature.as_ref())
                        .map_err(|_| XRPLError::FailedToEncodeSignature)?,
                )
                .to_vec(),
            ),
            _ => return Err(XRPLError::UnsupportedKeyType),
        };

        Ok(XRPLSigner {
            account: XRPLAccountId::from(&signer.pub_key),
            signing_pub_key: signer.pub_key,
            txn_signature,
        })
    }
}

#[cw_serde]
pub struct XRPLSignedTx {
    pub unsigned_tx: XRPLUnsignedTx,
    pub signers: Vec<XRPLSigner>,
    pub unsigned_tx_hash: HexTxHash,
    pub cc_id: Option<CrossChainId>,
}

impl XRPLSignedTx {
    pub fn new(
        unsigned_tx: XRPLUnsignedTx,
        signers: Vec<XRPLSigner>,
        unsigned_tx_hash: HexTxHash,
        cc_id: Option<CrossChainId>,
    ) -> Self {
        Self {
            unsigned_tx,
            signers,
            unsigned_tx_hash,
            cc_id,
        }
    }
}

// HASHING LOGIC

fn xrpl_hash(prefix: [u8; 4], tx_blob: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512::new_with_prefix(prefix);
    hasher.update(tx_blob);
    let digest: [u8; 64] = hasher.finalize().into();
    digest[..32].try_into().expect("digest should be 32 bytes")
}

pub fn hash_unsigned_tx(unsigned_tx: &XRPLUnsignedTx) -> Result<HexTxHash, XRPLError> {
    let encoded_unsigned_tx =
        serde_json::to_vec(unsigned_tx).map_err(|_| XRPLError::FailedToSerialize)?;

    let hash: [u8; 32] = Sha256::digest(encoded_unsigned_tx.as_slice()).into();
    Ok(HexTxHash::new(hash))
}

pub fn hash_signed_tx(encoded_signed_tx: &[u8]) -> Result<HexTxHash, XRPLError> {
    Ok(HexTxHash::new(xrpl_hash(
        SIGNED_TRANSACTION_HASH_PREFIX,
        encoded_signed_tx,
    )))
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
    // This currency is disallowed in XRPL
    pub const XRP: Self = Self(XRP_RESERVED_CURRENCY);

    // https://xrpl.org/docs/references/protocol/binary-format#currency-codes
    pub fn new(s: &str) -> Result<Self, XRPLError> {
        let bytes = Self::parse_standard(s)
            .or_else(|| Self::parse_non_standard(s))
            .ok_or_else(|| XRPLError::InvalidCurrency(s.to_string()))?;

        if Self::is_reserved(bytes) {
            return Err(XRPLError::ReservedCurrency(s.to_string()));
        }

        Ok(Self(bytes))
    }

    fn parse_standard(s: &str) -> Option<[u8; XRPL_CURRENCY_LENGTH]> {
        if STANDARD_CURRENCY_CODE_REGEX.is_match(s) {
            let mut bytes = [0u8; XRPL_CURRENCY_LENGTH];
            bytes[12..15].copy_from_slice(s.as_bytes());
            Some(bytes)
        } else {
            None
        }
    }

    fn parse_non_standard(s: &str) -> Option<[u8; XRPL_CURRENCY_LENGTH]> {
        if NON_STANDARD_CURRENCY_CODE_REGEX.is_match(s) && !s.starts_with("00") {
            HexBinary::from_hex(s).ok()?.as_slice().try_into().ok()
        } else {
            None
        }
    }

    fn is_reserved(bytes: [u8; XRPL_CURRENCY_LENGTH]) -> bool {
        bytes == XRP_RESERVED_CURRENCY || bytes == ZERO_RESERVED_CURRENCY
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

impl From<XRPLCurrency> for [u8; XRPL_CURRENCY_LENGTH] {
    fn from(currency: XRPLCurrency) -> [u8; XRPL_CURRENCY_LENGTH] {
        currency.as_bytes()
    }
}

impl fmt::Display for XRPLCurrency {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match self.0[0] {
            0x00 => {
                // standard currency
                std::str::from_utf8(&self.0[12..15])
                    .expect("standard currency code should always be valid UTF-8")
                    .to_string()
            }
            _ => {
                // non-standard currency
                HexBinary::from(self.0).to_string()
            }
        };
        write!(f, "{}", str)
    }
}

impl TryFrom<String> for XRPLCurrency {
    type Error = XRPLError;

    fn try_from(s: String) -> Result<Self, XRPLError> {
        XRPLCurrency::new(&s)
    }
}

impl PrimaryKey<'_> for XRPLCurrency {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = XRPLCurrency;
    type SuperSuffix = XRPLCurrency;

    fn key(&self) -> Vec<Key> {
        self.0.key()
    }
}

impl KeyDeserialize for XRPLCurrency {
    type Output = XRPLCurrency;
    const KEY_ELEMS: u16 = 1;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        let inner = <[u8; XRPL_CURRENCY_LENGTH]>::from_vec(value)?;
        Ok(XRPLCurrency(inner))
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

    pub fn as_bytes(&self) -> Result<[u8; 8], XRPLError> {
        Ok(if self.mantissa == 0 {
            0x8000000000000000u64.to_be_bytes()
        } else {
            // not xrp-bit | positive bit | 8 bits exponent | 54 bits mantissa
            (0xC000000000000000u64
                | (u64::try_from(
                    self.exponent
                        .checked_add(97)
                        .ok_or(XRPLError::ExponentOverflow)?,
                )
                .map_err(|_| XRPLError::InvalidExponent)?
                    << 54)
                | self.mantissa)
                .to_be_bytes()
        })
    }

    pub fn is_zero(&self) -> bool {
        self.mantissa == 0
    }
}

impl PartialOrd for XRPLTokenAmount {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let (self_mantissa, other_mantissa, _min_exponent) =
            scale_to_min_exponent(self, other).expect("scale_to_min_exponent should not fail");

        Some(self_mantissa.cmp(&other_mantissa))
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
                    &s[loc.checked_add(1).ok_or(XRPLError::InvalidTokenAmount {
                        reason: "exponent out of bounds".to_string(),
                    })?..],
                );
                (
                    base,
                    i64::from_str(exp).map_err(|_| XRPLError::InvalidTokenAmount {
                        reason: "invalid exponent".to_string(),
                    })?,
                )
            }
        };

        if base_part.is_empty() {
            return Err(XRPLError::InvalidTokenAmount {
                reason: "base part empty".to_string(),
            });
        }

        let (mut digits, decimal_offset): (String, _) = match base_part.find('.') {
            None => (base_part.to_string(), 0),
            Some(loc) => {
                let (lead, trail) = (
                    &base_part[..loc],
                    &base_part[loc.checked_add(1).ok_or(XRPLError::InvalidTokenAmount {
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
                return Err(XRPLError::InvalidTokenAmount {
                    reason: "overflow".to_string(),
                });
            }
        };

        if digits.starts_with('-') {
            return Err(XRPLError::InvalidTokenAmount {
                reason: "negative amount".to_string(),
            });
        }

        if digits.starts_with('+') {
            digits = digits[1..].to_string();
        }

        let mantissa =
            Uint256::from_str(digits.as_str()).map_err(|e| XRPLError::InvalidTokenAmount {
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

impl Add for XRPLTokenAmount {
    type Output = Result<XRPLTokenAmount, XRPLError>;

    fn add(self, rhs: XRPLTokenAmount) -> Self::Output {
        let (left_mantissa, right_mantissa, min_exponent) = scale_to_min_exponent(&self, &rhs)?;

        let result_mantissa = left_mantissa
            .checked_add(right_mantissa)
            .map_err(|_| XRPLError::AdditionOverflow)?;

        let (mantissa, exponent) = canonicalize_mantissa(result_mantissa, min_exponent)?;
        Ok(XRPLTokenAmount::new(mantissa, exponent))
    }
}

impl Sub for XRPLTokenAmount {
    type Output = Result<XRPLTokenAmount, XRPLError>;

    fn sub(self, rhs: XRPLTokenAmount) -> Self::Output {
        let (left_mantissa, right_mantissa, min_exponent) = scale_to_min_exponent(&self, &rhs)?;

        if left_mantissa < right_mantissa {
            return Err(XRPLError::Underflow);
        }

        let result_mantissa = left_mantissa
            .checked_sub(right_mantissa)
            .map_err(|_| XRPLError::SubtractionUnderflow)?;

        let (mantissa, exponent) = canonicalize_mantissa(result_mantissa, min_exponent)?;
        Ok(XRPLTokenAmount::new(mantissa, exponent))
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

#[cw_serde]
pub struct XRPLCrossCurrencyOptions {
    pub send_max: XRPLPaymentAmount,
    pub paths: Option<XRPLPathSet>,
}

#[cw_serde]
pub struct XRPLPathSet {
    pub paths: Vec<XRPLPath>,
}

impl fmt::Display for XRPLPathSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let paths: Vec<String> = self.paths.iter().map(|path| path.to_string()).collect();
        write!(f, "[{}]", paths.join(", "))
    }
}

#[cw_serde]
pub struct XRPLPath {
    pub steps: Vec<XRPLPathStep>,
}

impl fmt::Display for XRPLPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let steps: Vec<String> = self.steps.iter().map(|step| step.to_string()).collect();
        write!(f, "[{}]", steps.join(", "))
    }
}

#[cw_serde]
pub enum XRPLPathStep {
    Account(XRPLAccountId),
    Currency(XRPLCurrency),
    XRP,
    Issuer(XRPLAccountId),
    Token(XRPLToken),
}

impl fmt::Display for XRPLPathStep {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            XRPLPathStep::Account(account) => write!(f, "Account({})", account),
            XRPLPathStep::Currency(currency) => write!(f, "Currency({})", currency),
            XRPLPathStep::XRP => write!(f, "XRP"),
            XRPLPathStep::Issuer(issuer) => write!(f, "Issuer({})", issuer),
            XRPLPathStep::Token(token) => write!(f, "Token({})", token),
        }
    }
}

// always called when XRPLTokenAmount instantiated
// see https://github.com/XRPLF/xrpl-dev-portal/blob/82da0e53a8d6cdf2b94a80594541d868b4d03b94/content/_code-samples/tx-serialization/py/xrpl_num.py#L19
pub fn canonicalize_mantissa(
    mut mantissa: Uint256,
    mut exponent: i64,
) -> Result<(u64, i64), XRPLError> {
    let ten = Uint256::from(10u8);

    while mantissa < MIN_MANTISSA.into() && exponent > MIN_EXPONENT {
        mantissa = mantissa
            .checked_mul(ten)
            .map_err(|_| XRPLError::MultiplicationOverflow)?;

        exponent = exponent
            .checked_sub(1)
            .ok_or(XRPLError::SubtractionUnderflow)?;
    }

    while mantissa > MAX_MANTISSA.into() && exponent > MIN_EXPONENT {
        if exponent >= MAX_EXPONENT {
            return Err(XRPLError::ExponentOverflow);
        }

        mantissa = mantissa
            .checked_div(ten)
            .map_err(|_| XRPLError::DivisionByZero)?;

        exponent = exponent.checked_add(1).ok_or(XRPLError::AdditionOverflow)?;
    }

    if exponent < MIN_EXPONENT || mantissa < MIN_MANTISSA.into() {
        return Ok((0, 1));
    }

    if exponent > MAX_EXPONENT {
        Err(XRPLError::ExponentOverflow)?;
    }

    if mantissa > MAX_MANTISSA.into() {
        Err(XRPLError::MantissaOverflow)?;
    }

    let mantissa = u64::from_be_bytes(
        mantissa.to_be_bytes()[24..32]
            .try_into()
            .expect("mantissa should be 8 bytes"),
    );

    Ok((mantissa, exponent))
}

pub fn canonicalize_token_amount(
    amount: Uint256,
    decimals: u8,
) -> Result<XRPLTokenAmount, XRPLError> {
    let neg_decimals = i64::from(decimals)
        .checked_neg()
        .ok_or(XRPLError::InvalidDecimals(decimals))?;

    let (mantissa, exponent) = canonicalize_mantissa(amount, neg_decimals)?;
    Ok(XRPLTokenAmount::new(mantissa, exponent))
}

pub fn scale_to_decimals(
    amount: XRPLTokenAmount,
    destination_decimals: u8,
) -> Result<Uint256, XRPLError> {
    if amount.mantissa == 0 {
        return Ok(Uint256::zero());
    }

    let mantissa = Uint256::from(amount.mantissa);
    let ten = Uint256::from(10u8);

    let adjusted_exponent = amount
        .exponent
        .checked_add(i64::from(destination_decimals))
        .ok_or(XRPLError::AdditionOverflow)?;

    if adjusted_exponent >= 0 {
        let scaling_factor = ten
            .checked_pow(
                adjusted_exponent
                    .try_into()
                    // adjusted exponent is positive and within u32 range
                    .map_err(|_| XRPLError::InvalidExponent)?,
            )
            .map_err(|_| XRPLError::ExponentiationOverflow)?;

        let scaled_mantissa = mantissa
            .checked_mul(scaling_factor)
            .map_err(|_| XRPLError::MultiplicationOverflow)?;

        Ok(scaled_mantissa)
    } else {
        ten.checked_pow(
            adjusted_exponent
                .checked_neg()
                .ok_or(XRPLError::NegationOverflow)?
                .try_into()
                .map_err(|_| XRPLError::InvalidExponent)?,
        )
        .map(|scaling_factor| {
            let quotient = mantissa
                .checked_div(scaling_factor)
                .map_err(|_| XRPLError::DivisionByZero)?;

            Ok(quotient)
        })
        .unwrap_or(Ok(Uint256::zero()))
    }
}

pub fn scale_to_min_exponent(
    left: &XRPLTokenAmount,
    right: &XRPLTokenAmount,
) -> Result<(Uint256, Uint256, i64), XRPLError> {
    let min_exponent = min(left.exponent, right.exponent);
    let ten = Uint256::from(10u8);

    let left_mantissa = Uint256::from(left.mantissa)
        .checked_mul(
            ten.checked_pow(
                u32::try_from(
                    left.exponent
                        .checked_sub(min_exponent)
                        .ok_or(XRPLError::SubtractionUnderflow)?,
                )
                .map_err(|_| XRPLError::InvalidExponent)?,
            )
            .map_err(|_| XRPLError::ExponentiationOverflow)?,
        )
        .map_err(|_| XRPLError::MultiplicationOverflow)?;

    let right_mantissa = Uint256::from(right.mantissa)
        .checked_mul(
            ten.checked_pow(
                u32::try_from(
                    right
                        .exponent
                        .checked_sub(min_exponent)
                        .ok_or(XRPLError::SubtractionUnderflow)?,
                )
                .map_err(|_| XRPLError::InvalidExponent)?,
            )
            .map_err(|_| XRPLError::ExponentiationOverflow)?,
        )
        .map_err(|_| XRPLError::MultiplicationOverflow)?;

    Ok((left_mantissa, right_mantissa, min_exponent))
}

fn convert_scaled_uint256_to_u64(value: Uint256) -> u64 {
    let mut last_8 = [0u8; 8];
    last_8.copy_from_slice(&value.to_be_bytes()[24..32]);
    u64::from_be_bytes(last_8)
}

fn convert_scaled_uint256_to_drops(value: Uint256) -> Result<u64, XRPLError> {
    if value.gt(&XRP_MAX_UINT.into()) {
        return Err(XRPLError::DropsTooLarge);
    }

    Ok(convert_scaled_uint256_to_u64(value))
}

// Converts XRP drops to the destination chain's token amount.
pub fn scale_from_drops(drops: u64, destination_decimals: u8) -> Result<Uint256, XRPLError> {
    if drops > XRP_MAX_UINT {
        return Err(XRPLError::DropsTooLarge);
    }

    if destination_decimals > 82 {
        return Err(XRPLError::InvalidDecimals(destination_decimals));
    }

    let source_amount = Uint256::from(drops);
    if XRP_DECIMALS == destination_decimals {
        return Ok(source_amount);
    }

    let ten = Uint256::from(10u8);
    let scaling_factor = ten
        .checked_pow(XRP_DECIMALS.abs_diff(destination_decimals).into())
        .map_err(|_| XRPLError::ExponentiationOverflow)?;

    let destination_amount = if XRP_DECIMALS > destination_decimals {
        source_amount
            .checked_div(scaling_factor)
            .map_err(|_| XRPLError::DivisionByZero)?
    } else {
        source_amount
            .checked_mul(scaling_factor)
            .map_err(|_| XRPLError::MultiplicationOverflow)?
    };

    Ok(destination_amount)
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

    let ten = Uint256::from(10u8);
    let scaling_factor = ten
        .checked_pow(source_decimals.abs_diff(XRP_DECIMALS).into())
        .map_err(|_| XRPLError::ExponentiationOverflow)?;

    let (destination_amount, dust) = if source_decimals > XRP_DECIMALS {
        let quotient = source_amount
            .checked_div(scaling_factor)
            .map_err(|_| XRPLError::DivisionByZero)?;

        let product = quotient
            .checked_mul(scaling_factor)
            .map_err(|_| XRPLError::MultiplicationOverflow)?;

        let remainder = source_amount
            .checked_sub(product)
            .map_err(|_| XRPLError::SubtractionUnderflow)?;

        (quotient, remainder)
    } else {
        let product = source_amount
            .checked_mul(scaling_factor)
            .map_err(|_| XRPLError::MultiplicationOverflow)?;

        (product, Uint256::zero())
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
    fn test_canonicalize_token_amount() {
        assert_eq!(
            canonicalize_token_amount(Uint256::one(), 18).unwrap(),
            XRPLTokenAmount::new(1_000_000_000_000_000u64, -33)
        );

        assert_eq!(
            canonicalize_token_amount(Uint256::from(1_000_000_000_000_000_000u64), 18).unwrap(),
            XRPLTokenAmount::new(1_000_000_000_000_000u64, -15)
        );

        assert_eq!(
            canonicalize_token_amount(Uint256::from(1_234_567_891_234_567_891u64), 18).unwrap(),
            XRPLTokenAmount::new(1_234_567_891_234_567u64, -15)
        );

        assert_eq!(
            canonicalize_token_amount(Uint256::from(1_234_567_891_234_567_891u64), 30).unwrap(),
            XRPLTokenAmount::new(1_234_567_891_234_567u64, -27)
        );

        assert_eq!(
            canonicalize_token_amount(Uint256::from(1_234_567_891_234_567_891u64), 6).unwrap(),
            XRPLTokenAmount::new(1_234_567_891_234_567u64, -3)
        );
    }

    #[test]
    fn test_scale_to_decimals() {
        let amount = XRPLTokenAmount::new(1_000_000_000_000_000u64, -33);
        assert_eq!(scale_to_decimals(amount, 18).unwrap(), Uint256::one());

        let amount = XRPLTokenAmount::new(1_000_000_000_000_000u64, -15);
        assert_eq!(
            scale_to_decimals(amount, 18).unwrap(),
            Uint256::from(1_000_000_000_000_000_000u64)
        );

        let amount = XRPLTokenAmount::new(1_234_567_891_234_567u64, -15);
        assert_eq!(
            scale_to_decimals(amount, 18).unwrap(),
            Uint256::from(1_234_567_891_234_567_000u64)
        );

        let amount = XRPLTokenAmount::new(1_234_567_891_234_567u64, -15);
        assert_eq!(
            scale_to_decimals(amount, 6).unwrap(),
            Uint256::from(1_234_567u64)
        );

        let amount = XRPLTokenAmount::new(9_999_999_999_999_999u64, 55);
        assert_eq!(
            scale_to_decimals(amount, 6).unwrap(),
            Uint256::try_from(
                "99999999999999990000000000000000000000000000000000000000000000000000000000000"
            )
            .unwrap()
        );

        let amount = XRPLTokenAmount::new(9_999_999_999_999_999u64, 56);
        let result = scale_to_decimals(amount, 6);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "multiplication overflow");
    }

    #[test]
    fn test_large_exponent_handling() {
        let amount = XRPLTokenAmount::new(9_999_999_999_999_999u64, 70);
        let result = scale_to_decimals(amount, 18);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "exponentiation overflow");
    }

    #[test]
    fn test_large_mantissa_handling() {
        let amount = XRPLTokenAmount::new(9_999_999_999_999_999u64, 0);
        let result = scale_to_decimals(amount, 18);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            Uint256::from(9999999999999999000000000000000000u128)
        );
    }

    #[test]
    fn test_small_mantissa_handling() {
        let amount = XRPLTokenAmount::new(9_999_999_999_999_999u64, MIN_EXPONENT);
        let result = scale_to_decimals(amount, 18);
        assert_eq!(result.unwrap(), Uint256::zero());
    }

    #[test]
    fn test_extreme_scaling_down() {
        let amount = XRPLTokenAmount::new(MAX_MANTISSA, MIN_EXPONENT);
        let result = scale_to_decimals(amount, 6);
        assert_eq!(result.unwrap(), Uint256::zero(),);
    }

    #[test]
    fn test_extreme_scaling_up() {
        let amount = XRPLTokenAmount::new(MIN_MANTISSA, MAX_EXPONENT);
        let result = scale_to_decimals(amount, 18);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "exponentiation overflow");
    }

    #[test]
    fn test_scale_from_drops() {
        assert_eq!(
            scale_from_drops(1_000_000, 18).unwrap(),
            Uint256::from(1_000_000_000_000_000_000u64)
        );
        assert_eq!(
            scale_from_drops(100000000000000000, 18).unwrap(),
            Uint256::from(100000000000000000000000000000u128)
        );
        assert_eq!(
            scale_from_drops(1_000_000, 6).unwrap(),
            Uint256::from(1_000_000u32)
        );
        assert_eq!(
            scale_from_drops(1_234_567, 18).unwrap(),
            Uint256::from(1_234_567_000_000_000_000u64)
        );
        assert_eq!(
            scale_from_drops(1_000_000, 6).unwrap(),
            Uint256::from(1_000_000u32)
        );
        assert_eq!(
            scale_from_drops(1_000_001, 5).unwrap(),
            Uint256::from(100_000u32)
        );
        assert_eq!(
            scale_from_drops(1_000_123, 3).unwrap(),
            Uint256::from(1_000u32)
        );
        assert_eq!(
            scale_from_drops(1_123_456_789, 3).unwrap(),
            Uint256::from(1_123_456u32)
        );
        assert_eq!(
            scale_from_drops(1_123_456_789, 1).unwrap(),
            Uint256::from(11_234u32)
        );
        assert_eq!(scale_from_drops(1, 5).unwrap(), Uint256::zero());
    }

    #[test]
    fn test_scale_from_invalid_drops() {
        let result = scale_from_drops(XRP_MAX_UINT + 1, 18);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "drops too large");
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
    fn test_xrpl_token_amount_add_same_exponent() {
        let x = XRPLTokenAmount::new(1_234_567_890_123_456, -5); // 0.01234567890123456
        let y = XRPLTokenAmount::new(6_543_210_987_654_321, -5); // 0.06543210987654321

        let result = x.add(y).unwrap();
        assert_eq!(result.mantissa, 7_777_778_877_777_777); // 0.07777778877777777
        assert_eq!(result.exponent, -5);
    }

    #[test]
    fn test_xrpl_token_amount_add_different_exponents() {
        let x = XRPLTokenAmount::new(9_876_543_210_987_654, -3); // 9876.543210987654
        let y = XRPLTokenAmount::new(1_234_567_890_123_456, -6); // 1.234567890123456

        let result = x.add(y).unwrap();
        assert_eq!(result.mantissa, 9_877_777_778_877_777); // 9877.777778877777
        assert_eq!(result.exponent, -3);
    }

    #[test]
    fn test_xrpl_token_amount_sub_same_exponent() {
        let x = XRPLTokenAmount::new(9_999_999_999_999_999, -5); // 0.09999999999999999
        let y = XRPLTokenAmount::new(1_234_567_890_123_456, -5); // 0.01234567890123456

        let result = x.sub(y).unwrap();
        assert_eq!(result.mantissa, 8_765_432_109_876_543); // 0.08765432109876543
        assert_eq!(result.exponent, -5);
    }

    #[test]
    fn test_xrpl_token_amount_sub_different_exponents() {
        let x = XRPLTokenAmount::new(9_876_543_210_987_654, -3); // 9876.543210987654
        let y = XRPLTokenAmount::new(1_234_567_890_123_456, -6); // 1.234567890123456

        let result = x.sub(y).unwrap();
        assert_eq!(result.mantissa, 9_875_308_643_097_530); // 9875.30864309753
        assert_eq!(result.exponent, -3);
    }

    #[test]
    fn test_xrpl_token_amount_add_overflow() {
        let x = XRPLTokenAmount::new(MAX_MANTISSA - 1, MAX_EXPONENT);
        let y = XRPLTokenAmount::new(2_000_000_000_000_000, MAX_EXPONENT);

        let result = x.add(y);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "exponent overflow");
    }

    #[test]
    fn test_xrpl_token_amount_sub_underflow() {
        let x = XRPLTokenAmount::new(1_000_000_000_000_000, -3);
        let y = XRPLTokenAmount::new(9_876_543_210_987_654, -3);

        let result = x.sub(y);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "underflow");
    }

    #[test]
    fn test_xrpl_token_amount_add_canonicalization() {
        let x = XRPLTokenAmount::new(MAX_MANTISSA - 1, 0);
        let y = XRPLTokenAmount::new(2_000_000_000_000_000, 0);

        let result = x.add(y).unwrap();
        assert_eq!(result.mantissa, 1199999999999999);
        assert_eq!(result.exponent, 1);
    }

    #[test]
    fn test_xrpl_token_amount_sub_exact_zero() {
        let x = XRPLTokenAmount::new(8_765_432_109_876_543, -5);
        let y = XRPLTokenAmount::new(8_765_432_109_876_543, -5);

        let result = x.sub(y).unwrap();
        assert_eq!(result.mantissa, 0);
        assert_eq!(result.exponent, 1);
    }

    #[test]
    fn test_xrpl_token_amount_edge_cases() {
        let x = XRPLTokenAmount::new(MIN_MANTISSA, MIN_EXPONENT);
        let y = XRPLTokenAmount::new(MIN_MANTISSA, MIN_EXPONENT);

        let result = x.add(y).unwrap();
        assert_eq!(result.mantissa, 2 * MIN_MANTISSA);
        assert_eq!(result.exponent, MIN_EXPONENT);
    }

    #[test]
    fn test_xrpl_payment_amount_add_drops() {
        let x = XRPLPaymentAmount::Drops(5_123_456);
        let y = XRPLPaymentAmount::Drops(2_000_000);

        let result = x.add(y).unwrap();
        assert_eq!(result, XRPLPaymentAmount::Drops(7_123_456));
    }

    #[test]
    fn test_xrpl_payment_amount_sub_drops() {
        let x = XRPLPaymentAmount::Drops(5_555_555);
        let y = XRPLPaymentAmount::Drops(5_555_555);

        let result = x.sub(y).unwrap();
        assert_eq!(result, XRPLPaymentAmount::Drops(0));
    }

    #[test]
    fn test_xrpl_payment_amount_add_issued() {
        let token = XRPLToken {
            issuer: XRPLAccountId::new([1; 20]),
            currency: XRPLCurrency::new("ETH").unwrap(),
        };

        let x = XRPLPaymentAmount::Issued(
            token.clone(),
            XRPLTokenAmount::new(1_000_000_000_000_000, -3),
        );
        let y = XRPLPaymentAmount::Issued(
            token.clone(),
            XRPLTokenAmount::new(5_000_000_000_000_000, -3),
        );

        let result = x.add(y).unwrap();
        assert_eq!(
            result,
            XRPLPaymentAmount::Issued(token, XRPLTokenAmount::new(6_000_000_000_000_000, -3))
        );
    }

    #[test]
    fn test_xrpl_payment_amount_sub_issued() {
        let token = XRPLToken {
            issuer: XRPLAccountId::new([0; 20]),
            currency: XRPLCurrency::new("USD").unwrap(),
        };

        let x = XRPLPaymentAmount::Issued(
            token.clone(),
            XRPLTokenAmount::new(1_234_567_891_234_567u64, -15),
        );
        let y = XRPLPaymentAmount::Issued(
            token.clone(),
            XRPLTokenAmount::new(1_234_567_891_234_567u64, -15),
        );

        let result = x.sub(y).unwrap();
        assert_eq!(
            result,
            XRPLPaymentAmount::Issued(token, XRPLTokenAmount::new(0, 1))
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

        let d1 = XRPLTokenAmount::new(1_000_000_000_000_000, -2);
        let d2 = XRPLTokenAmount::new(1_000_000_000_000_000, 0);
        assert_eq!(d1.partial_cmp(&d2), Some(std::cmp::Ordering::Less));

        let e1 = XRPLTokenAmount::new(1_000_000_000_000_000, -2);
        let e2 = XRPLTokenAmount::new(1_000_000_000_000_000, 1);
        assert_eq!(e1.partial_cmp(&e2), Some(std::cmp::Ordering::Less));

        let f1 = XRPLTokenAmount::ZERO;
        let f2 = XRPLTokenAmount::new(1_500_000_000_000_000, -15);
        assert_eq!(f1.partial_cmp(&f2), Some(std::cmp::Ordering::Less));
        assert_eq!(f2.partial_cmp(&f1), Some(std::cmp::Ordering::Greater));

        let g1 = XRPLTokenAmount::new(1_000_000_000_000_000, 1);
        let g2 = XRPLTokenAmount::new(1_000_000_000_000_000, -2);
        assert_eq!(g1.partial_cmp(&g2), Some(std::cmp::Ordering::Greater));
    }

    #[test]
    fn test_xrpl_token_amount_add_sub_large_exponent_diff() {
        let a1 = XRPLTokenAmount::from_str("2000000000000000e-21").unwrap();
        let a2 = XRPLTokenAmount::from_str("0e1").unwrap();

        let result = a1.clone().add(a2.clone()).unwrap();
        assert_eq!(result, XRPLTokenAmount::new(2000000000000000, -21));

        let result = a1.clone().sub(a2.clone()).unwrap();
        assert_eq!(result, XRPLTokenAmount::new(2000000000000000, -21));

        let b1 = XRPLTokenAmount::from_str("2000000000000000e-21").unwrap();
        let b2 = XRPLTokenAmount::from_str("1e1").unwrap();

        assert_eq!(b1.partial_cmp(&b2), Some(std::cmp::Ordering::Less));
        assert_eq!(b2.partial_cmp(&b1), Some(std::cmp::Ordering::Greater));
    }

    #[test]
    fn test_xrpl_token_key_deserialize() {
        let issuer = XRPLAccountId::from_str("rDTXLQ7ZKZVKz33zJbHjgVShjsBnqMBhmN").unwrap();
        let currency = XRPLCurrency::new("USD").unwrap();
        assert_eq!(
            XRPLToken::from_vec([issuer.as_bytes(), currency.as_bytes()].concat()).unwrap(),
            XRPLToken { issuer, currency }
        );
    }

    #[test]
    fn test_invalid_currency_formats() {
        assert!(XRPLCurrency::new("").is_err());
        assert!(XRPLCurrency::new("invalid").is_err());
        assert!(XRPLCurrency::new(
            "524C555344000000000000000000000000000000524C555344000000000000000000000000000000"
        )
        .is_err());
        assert!(XRPLCurrency::new("00524C5553440000000000000000000000000000").is_err());
    }

    #[test]
    fn test_valid_standard_currency() {
        let zeros_str = "000";
        let zeros = XRPLCurrency::new(zeros_str);
        assert!(zeros.is_ok());
        assert_eq!(zeros.unwrap().to_string(), zeros_str);

        let usd_str = "USD";
        let usd = XRPLCurrency::new(usd_str);
        assert!(usd.is_ok());
        assert_eq!(usd.unwrap().to_string(), usd_str);
    }

    #[test]
    fn test_valid_non_standard_currency() {
        let rlusd_hex = "524C555344000000000000000000000000000000";
        let rlusd = XRPLCurrency::new(rlusd_hex);
        assert!(rlusd.is_ok());
        assert_eq!(rlusd.unwrap().to_string(), rlusd_hex.to_lowercase());
    }

    #[test]
    fn test_reserved_standard_currency() {
        assert!(XRPLCurrency::new("XRP").is_err());
        assert!(XRPLCurrency::new("\0\0\0").is_err());
    }

    #[test]
    fn test_reserved_non_standard_currency() {
        assert!(XRPLCurrency::new("0000000000000000000000005852500000000000").is_err());
        assert!(XRPLCurrency::new("0000000000000000000000000000000000000000").is_err());
    }
}
