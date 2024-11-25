use std::fmt;
use std::str::FromStr;

use axelar_wasm_std::VerificationStatus;
use interchain_token_service::TokenId;
use router_api::{CrossChainId, FIELD_DELIMITER};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{from_json, Binary, HexBinary, StdResult, Uint128, Uint256};
use cw_storage_plus::{Key, KeyDeserialize, PrimaryKey};
use k256::ecdsa;
use k256::schnorr::signature::SignatureEncoding;
use multisig::key::PublicKey;
use multisig::key::Signature;
use ripemd::Ripemd160;
use sha2::Sha512;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use axelar_wasm_std::Participant;
use cosmwasm_std::Addr;
use axelar_wasm_std::nonempty;

use crate::error::XRPLError;

const XRPL_PAYMENT_DROPS_HASH_PREFIX: &[u8] = b"drops";
const XRPL_PAYMENT_ISSUED_HASH_PREFIX: &[u8] = b"issued";

const XRPL_ACCOUNT_ID_LENGTH: usize = 20;
const XRPL_CURRENCY_LENGTH: usize = 20;
const XRPL_TX_HASH_LENGTH: usize = 32;

#[cw_serde]
#[derive(Eq, Ord, PartialOrd)]
pub struct AxelarSigner {
    pub address: Addr,
    pub weight: u16,
    pub pub_key: PublicKey,
}

impl From<AxelarSigner> for Participant {
    fn from(signer: AxelarSigner) -> Self {
        let weight = nonempty::Uint128::try_from(Uint128::from(u128::from(signer.weight))).unwrap();
        Self {
            address: signer.address,
            weight,
        }
    }
}

#[cw_serde]
pub enum XRPLTxStatus {
    Pending,
    Succeeded,
    FailedOnChain,
    Inconclusive,
}

#[cw_serde]
#[derive(Eq, Hash)]
pub struct TxHash([u8; XRPL_TX_HASH_LENGTH]);

impl AsRef<[u8; XRPL_TX_HASH_LENGTH]> for TxHash {
    fn as_ref(&self) -> &[u8; XRPL_TX_HASH_LENGTH] {
        &self.0
    }
}

impl fmt::Display for TxHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", HexBinary::from(self.0))
    }
}

impl TxHash {
    pub fn new(hash: [u8; XRPL_TX_HASH_LENGTH]) -> Self {
        Self(hash)
    }
}

impl Into<[u8; XRPL_TX_HASH_LENGTH]> for TxHash {
    fn into(self) -> [u8; XRPL_TX_HASH_LENGTH] {
        self.0
    }
}

impl TryFrom<CrossChainId> for TxHash {
    type Error = XRPLError;
    fn try_from(cc_id: CrossChainId) -> Result<Self, XRPLError> {
        let message_id = cc_id.message_id.as_str();
        Ok(Self(
            HexBinary::from_hex(message_id)?
                .to_vec()
                .try_into()
                .map_err(|_| XRPLError::InvalidMessageId(message_id.to_string()))?
        ))
    }
}

impl From<TxHash> for HexBinary {
    fn from(hash: TxHash) -> Self {
        HexBinary::from(hash.0)
    }
}
impl TryFrom<HexBinary> for TxHash {
    type Error = XRPLError;

    fn try_from(tx_hash: HexBinary) -> Result<Self, XRPLError> {
        let slice: &[u8] = tx_hash.as_slice();
        slice.try_into()
    }
}

impl TryFrom<&[u8]> for TxHash {
    type Error = XRPLError;

    fn try_from(tx_hash: &[u8]) -> Result<Self, XRPLError> {
        Ok(Self(tx_hash.try_into().map_err(|_| XRPLError::InvalidTxId)?))
    }
}

impl<'a> PrimaryKey<'a> for TxHash {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = TxHash;
    type SuperSuffix = TxHash;

    fn key(&self) -> Vec<Key> {
        vec![Key::Ref(self.0.as_slice())]
    }
}

impl KeyDeserialize for TxHash {
    type Output = TxHash;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        from_json(Binary::from(value))
    }
}

pub mod tx_hash_hex {
    use super::TxHash;
    use cosmwasm_std::HexBinary;
    use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &TxHash, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        HexBinary::from(value.as_ref()).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<TxHash, D::Error>
    where
        D: Deserializer<'de>,
    {
        HexBinary::deserialize(deserializer)?
            .try_into()
            .map_err(Error::custom)
    }
}

impl Into<XRPLTxStatus> for VerificationStatus {
    fn into(self) -> XRPLTxStatus {
        match self {
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
#[derive(Ord, PartialOrd, Eq)]
pub struct Operator {
    pub address: HexBinary,
    pub weight: Uint256,
    pub signature: Option<Signature>,
}

impl Operator {
    pub fn with_signature(self, sig: Signature) -> Operator {
        Operator {
            address: self.address,
            weight: self.weight,
            signature: Some(sig),
        }
    }
}

#[cw_serde]
#[derive(Eq, Hash)]
pub struct XRPLToken {
    #[serde(with = "xrpl_account_id_string")]
    #[schemars(with = "String")] // necessary attribute in conjunction with #[serde(with ...)]
    pub issuer: XRPLAccountId,
    pub currency: XRPLCurrency,
}

#[cw_serde]
pub enum XRPLTokenOrXrp {
    Issued(XRPLToken),
    Xrp,
}

#[cw_serde]
pub struct XRPLTokenInfo {
    pub xrpl_token: XRPLToken,
    pub canonical_decimals: u8,
}

const ITS_INTERCHAIN_TOKEN_ID: &[u8] = "its-interchain-token-id".as_bytes();
const XRP_DEPLOYER: &[u8; 20] = &[0u8; 20];

impl XRPLTokenOrXrp {
    pub fn token_id(&self) -> TokenId {
        let (deployer, salt) = match self {
            // TODO: Hash domain separation for XRP vs Issued.
            XRPLTokenOrXrp::Issued(token) => {
                // TODO: Assert token.issuer != xrpl_multisig.
                (token.issuer.as_ref(), token.currency.clone().as_bytes().to_vec())
            },
            XRPLTokenOrXrp::Xrp => (XRP_DEPLOYER, "XRP".as_bytes().to_vec()),
        };
        let prefix = Keccak256::digest(ITS_INTERCHAIN_TOKEN_ID);
        let token_id = Keccak256::digest(vec![prefix.as_slice(), deployer, salt.as_slice()].concat());
        let token_id_slice: &[u8; 32] = token_id.as_ref();
        TokenId::new(token_id_slice.clone())
    }
}

#[cw_serde]
#[derive(Eq, Hash)]
pub enum XRPLPaymentAmount {
    Drops(u64),
    Issued(XRPLToken, XRPLTokenAmount),
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
            },
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
            },
        }

        hasher.finalize().into()
    }
}

impl fmt::Display for XRPLPaymentAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            XRPLPaymentAmount::Drops(drops) => write!(f, "Drops({})", drops),
            XRPLPaymentAmount::Issued(token, amount) => write!(f, "TokenAmount({:?},{:?})", token, amount),
        }
    }
}

#[cw_serde]
pub struct XRPLMemo(pub HexBinary);

impl From<XRPLMemo> for HexBinary {
    fn from(memo: XRPLMemo) -> Self {
        memo.0
    }
}

#[cw_serde]
pub enum XRPLSequence {
    Plain(u32),
    Ticket(u32),
}

impl From<XRPLSequence> for u32 {
    fn from(value: XRPLSequence) -> Self {
        match value {
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

impl XRPLUnsignedTx {
    pub fn sequence(&self) -> &XRPLSequence {
        match self {
            XRPLUnsignedTx::Payment(tx) => &tx.sequence,
            XRPLUnsignedTx::TicketCreate(tx) => &tx.sequence,
            XRPLUnsignedTx::SignerListSet(tx) => &tx.sequence,
            XRPLUnsignedTx::TrustSet(tx) => &tx.sequence,
        }
    }
    pub fn sequence_number_increment(&self, status: XRPLTxStatus) -> u32 {
        if status == XRPLTxStatus::Pending || status == XRPLTxStatus::Inconclusive {
            return 0;
        }

        match self {
            XRPLUnsignedTx::Payment(tx) => match tx.sequence {
                XRPLSequence::Plain(_) => 1,
                XRPLSequence::Ticket(_) => 0,
            },
            XRPLUnsignedTx::SignerListSet(tx) => match tx.sequence {
                XRPLSequence::Plain(_) => 1,
                XRPLSequence::Ticket(_) => 0,
            },
            XRPLUnsignedTx::TicketCreate(tx) => match status {
                XRPLTxStatus::Succeeded => tx.ticket_count + 1,
                XRPLTxStatus::FailedOnChain => 1,
                XRPLTxStatus::Inconclusive | XRPLTxStatus::Pending => unreachable!(),
            },
            XRPLUnsignedTx::TrustSet(tx) => match tx.sequence {
                XRPLSequence::Plain(_) => 1,
                XRPLSequence::Ticket(_) => 0,
            },
        }
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

    pub fn from_bytes(bytes: [u8; XRPL_ACCOUNT_ID_LENGTH]) -> Self {
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
        let bytes: [u8; XRPL_ACCOUNT_ID_LENGTH] = hex.as_slice().try_into().map_err(|_| XRPLError::InvalidAddress(hex.to_string()))?;
        Ok(Self(bytes))
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

#[test]
fn test_xrpl_account_id_from_string() {
    let xrpl_account = "rNM8ue6DZpneFC4gBEJMSEdbwNEBZjs3Dy";
    let expected_bytes: &[u8; 20] = &[146, 136, 70, 186, 245, 155, 212, 140, 40, 177, 49, 133, 84, 114, 208, 76, 147, 187, 208, 183];
    assert_eq!(XRPLAccountId::from_str(xrpl_account).unwrap().as_ref(), expected_bytes);
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

    use super::XRPLAccountId;
    use serde::{Deserialize, Deserializer, Serializer};

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

impl TryFrom<(multisig::key::Signature, multisig::msg::Signer)> for XRPLSigner {
    type Error = XRPLError;

    fn try_from(
        (signature, axelar_signer): (multisig::key::Signature, multisig::msg::Signer),
    ) -> Result<Self, XRPLError> {
        let txn_signature = match axelar_signer.pub_key {
            multisig::key::PublicKey::Ecdsa(_) => {
                HexBinary::from(
                    ecdsa::Signature::to_der(
                        &ecdsa::Signature::try_from(signature.as_ref())
                            .map_err(|_| XRPLError::FailedToEncodeSignature)?,
                    )
                    .to_vec(),
                )
            },
            _ => unimplemented!("Unsupported public key type"),
        };

        Ok(XRPLSigner {
            account: XRPLAccountId::from(&axelar_signer.pub_key),
            signing_pub_key: axelar_signer.pub_key.clone(),
            txn_signature,
        })
    }
}

#[cw_serde]
pub struct XRPLSignedTx {
    pub unsigned_tx: XRPLUnsignedTx,
    pub signers: Vec<XRPLSigner>,
}

impl XRPLSignedTx {
    pub fn new(unsigned_tx: XRPLUnsignedTx, signers: Vec<XRPLSigner>) -> Self {
        Self {
            unsigned_tx,
            signers,
        }
    }
}

// HASHING LOGIC

const HASH_PREFIX_SIGNED_TRANSACTION: [u8; 4] = [0x54, 0x58, 0x4E, 0x00];
const HASH_PREFIX_UNSIGNED_TX_MULTI_SIGNING: [u8; 4] = [0x53, 0x4D, 0x54, 0x00];

fn xrpl_hash(prefix: [u8; 4], tx_blob: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512::new_with_prefix(prefix);
    hasher.update(tx_blob);
    let digest: [u8; 64] = hasher.finalize().into();
    digest[..32].try_into().unwrap()
}

pub fn hash_unsigned_tx(unsigned_tx: &XRPLUnsignedTx) -> Result<TxHash, XRPLError> {
    let encoded_unsigned_tx =
        serde_json::to_vec(unsigned_tx).map_err(|_| XRPLError::FailedToSerialize)?;

    Ok(TxHash::new(Sha256::digest(encoded_unsigned_tx).into()))
}

pub fn hash_signed_tx(encoded_signed_tx: &[u8]) -> Result<TxHash, XRPLError> {
    Ok(TxHash::new(xrpl_hash(
        HASH_PREFIX_SIGNED_TRANSACTION,
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
        HASH_PREFIX_UNSIGNED_TX_MULTI_SIGNING,
        tx_blob.as_slice(),
    ))
}

#[cw_serde]
#[derive(Eq, Hash)]
pub struct XRPLCurrency([u8; XRPL_CURRENCY_LENGTH]);

impl XRPLCurrency {
    pub fn new(s: &str) -> Result<Self, XRPLError> {
        if s.len() != 3 || s == "XRP" || !s.chars().all(|c| ALLOWED_CURRENCY_CHARS.contains(c)) {
            return Err(XRPLError::InvalidCurrency);
        }

        let mut buffer = [0u8; XRPL_CURRENCY_LENGTH];
        buffer[12..15].copy_from_slice(s.as_bytes());
        Ok(XRPLCurrency(buffer))
    }

    pub fn as_bytes(&self) -> [u8; XRPL_CURRENCY_LENGTH] {
        self.0
    }

    pub fn to_string(&self) -> String {
        std::str::from_utf8(&self.0[12..15])
            .expect("Currency code should always be valid UTF-8")
            .to_string()
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
        write!(f, "{}", self.to_string())
    }
}

const ALLOWED_CURRENCY_CHARS: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789?!@#$%^&*<>(){}[]|";

impl TryFrom<String> for XRPLCurrency {
    type Error = XRPLError;

    fn try_from(s: String) -> Result<Self, XRPLError> {
        XRPLCurrency::new(&s)
    }
}

impl<'a> PrimaryKey<'a> for XRPLCurrency {
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

    fn from_vec(value: Vec<u8>) -> cosmwasm_std::StdResult<Self::Output> {
        let inner = <[u8; XRPL_CURRENCY_LENGTH]>::from_vec(value)?;
        Ok(XRPLCurrency(inner))
    }
}

const MIN_MANTISSA: u64 = 1_000_000_000_000_000;
const MAX_MANTISSA: u64 = 10_000_000_000_000_000 - 1;
const MIN_EXPONENT: i64 = -96;
const MAX_EXPONENT: i64 = 80;

pub const XRPL_TOKEN_MIN_MANTISSA: u64 = MIN_MANTISSA;
pub const XRPL_TOKEN_MAX_MANTISSA: u64 = MAX_MANTISSA;
pub const XRPL_TOKEN_MIN_EXPONENT: i64 = MIN_EXPONENT;
pub const XRPL_TOKEN_MAX_EXPONENT: i64 = MAX_EXPONENT;

// XRPLTokenAmount always in canonicalized XRPL mantissa-exponent format,
// such that MIN_MANTISSA <= mantissa <= MAX_MANTISSA (or equal to zero), MIN_EXPONENT <= exponent <= MAX_EXPONENT,
// In XRPL generally it can be decimal and even negative (!) but in our case that doesn't apply.
#[cw_serde]
#[derive(Eq, Hash)]
pub struct XRPLTokenAmount {
    mantissa: u64,
    exponent: i64,
}

impl XRPLTokenAmount {
    pub const MAX: XRPLTokenAmount = XRPLTokenAmount {
        mantissa: MAX_MANTISSA,
        exponent: MAX_EXPONENT,
    };

    pub fn new(mantissa: u64, exponent: i64) -> Self {
        assert!(
            mantissa == 0
                || ((MIN_MANTISSA..=MAX_MANTISSA).contains(&mantissa)
                    && (MIN_EXPONENT..=MAX_EXPONENT).contains(&exponent))
        );
        Self { mantissa, exponent }
    }

    pub fn as_bytes(&self) -> [u8; 8] {
        if self.mantissa == 0 {
            0x8000000000000000u64.to_be_bytes()
        } else {
            // not xrp-bit | positive bit | 8 bits exponent | 54 bits mantissa
            (0xC000000000000000u64 | ((self.exponent + 97) as u64) << 54 | self.mantissa)
                .to_be_bytes()
        }
    }
}

impl TryFrom<String> for XRPLTokenAmount {
    type Error = XRPLError;

    fn try_from(s: String) -> Result<Self, XRPLError> {
        let exp_separator: &[_] = &['e', 'E'];

        let (base_part, exponent_value) = match s.find(exp_separator) {
            None => (s.as_str(), 0),
            Some(loc) => {
                let (base, exp) = (&s[..loc], &s[loc + 1..]);
                (base, i64::from_str(exp).map_err(|_| XRPLError::InvalidAmount { reason: "invalid exponent".to_string() })?)
            }
        };

        if base_part.is_empty() {
            return Err(XRPLError::InvalidAmount { reason: "base part empty".to_string() });
        }

        let (mut digits, decimal_offset): (String, _) = match base_part.find('.') {
            None => (base_part.to_string(), 0),
            Some(loc) => {
                let (lead, trail) = (&base_part[..loc], &base_part[loc + 1..]);
                let mut digits = String::from(lead);
                digits.push_str(trail);
                let trail_digits = trail.chars().filter(|c| *c != '_').count();
                (digits, trail_digits as i64)
            }
        };

        let exponent = match decimal_offset.checked_sub(exponent_value) {
            Some(exponent) => exponent,
            None => {
                return Err(XRPLError::InvalidAmount { reason: "overflow".to_string() });
            }
        };

        if digits.starts_with('-') {
            return Err(XRPLError::InvalidAmount { reason: "negative amount".to_string() });
        }

        if digits.starts_with('+') {
            digits = digits[1..].to_string();
        }

        let mantissa = Uint256::from_str(digits.as_str()).map_err(|e| XRPLError::InvalidAmount { reason: e.to_string() })?;

        let (mantissa, exponent) = canonicalize_mantissa(mantissa, exponent * -1)?;

        Ok(XRPLTokenAmount::new(mantissa, exponent))
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

#[cw_serde]
pub struct XRPLPath {
    pub steps: Vec<XRPLPathStep>,
}

#[cw_serde]
pub enum XRPLPathStep {
    Account(XRPLAccountId),
    Currency(XRPLCurrency),
    XRP,
    Issuer(XRPLAccountId),
    Token(XRPLToken),
}

// always called when XRPLTokenAmount instantiated
// see https://github.com/XRPLF/xrpl-dev-portal/blob/82da0e53a8d6cdf2b94a80594541d868b4d03b94/content/_code-samples/tx-serialization/py/xrpl_num.py#L19
pub fn canonicalize_mantissa(
    mut mantissa: Uint256,
    mut exponent: i64,
) -> Result<(u64, i64), XRPLError> {
    let ten = Uint256::from(10u128);

    while mantissa < MIN_MANTISSA.into() && exponent > MIN_EXPONENT {
        mantissa *= ten;
        exponent -= 1;
    }

    while mantissa > MAX_MANTISSA.into() && exponent > MIN_EXPONENT {
        if exponent >= MAX_EXPONENT {
            return Err(XRPLError::InvalidAmount {
                reason: "overflow".to_string(),
            });
        }
        mantissa /= ten;
        exponent += 1;
    }

    if exponent < MIN_EXPONENT || mantissa < MIN_MANTISSA.into() {
        return Ok((0, 1));
    }

    if exponent > MAX_EXPONENT || mantissa > MAX_MANTISSA.into() {
        return Err(XRPLError::InvalidAmount {
            reason: format!("overflow exponent {} mantissa {}", exponent, mantissa).to_string(),
        });
    }

    let mantissa = u64::from_be_bytes(mantissa.to_be_bytes()[24..32].try_into().expect("mantissa should be 8 bytes"));

    Ok((mantissa, exponent))
}

pub fn canonicalize_token_amount(
    amount: Uint256,
    decimals: u8,
) -> Result<XRPLTokenAmount, XRPLError> {
    let (mantissa, exponent) = canonicalize_mantissa(amount, -i64::from(decimals))?;
    Ok(XRPLTokenAmount::new(mantissa, exponent))
}

#[cfg(test)]
mod tests {
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
}
