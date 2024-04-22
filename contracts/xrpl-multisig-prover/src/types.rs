use axelar_wasm_std::VerificationStatus;
use connection_router_api::CrossChainId;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{from_json, HexBinary, Binary, StdResult, Uint256, Uint128};
use cw_storage_plus::{Key, KeyDeserialize, PrimaryKey};
use k256::ecdsa;
use k256::schnorr::signature::SignatureEncoding;
use multisig::key::Signature;
use multisig::key::PublicKey;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use voting_verifier::events::parse_message_id;
use crate::axelar_workers::AxelarSigner;
use crate::error::ContractError;

#[cw_serde]
pub enum TransactionStatus {
    Pending,
    Succeeded,
    FailedOnChain,
    Inconclusive,
}

#[cw_serde]
pub struct TxHash(pub HexBinary);

impl TryFrom<CrossChainId> for TxHash {
    type Error = ContractError;
    fn try_from(cc_id: CrossChainId) -> Result<Self, ContractError> {
        let (tx_id, _event_index) = parse_message_id(&cc_id.id).map_err(|_e| ContractError::InvalidMessageID(cc_id.id.to_string()))?;
        Ok(Self(HexBinary::from_hex(tx_id.to_ascii_lowercase().as_str())?))
    }
}

impl Into<HexBinary> for TxHash {
    fn into(self) -> HexBinary {
        self.0
    }
}

impl Into<TransactionStatus> for VerificationStatus {
    fn into(self) -> TransactionStatus {
        match self {
            VerificationStatus::SucceededOnChain => TransactionStatus::Succeeded,
            VerificationStatus::FailedOnChain => TransactionStatus::FailedOnChain,
            _ => TransactionStatus::Inconclusive,
        }
    }
}

#[cw_serde]
pub struct TransactionInfo {
    pub status: TransactionStatus,
    pub unsigned_contents: XRPLUnsignedTx,
    pub original_message_id: Option<CrossChainId>,
}

impl From<HexBinary> for TxHash {
    fn from(id: HexBinary) -> Self {
        Self(id)
    }
}

impl From<&[u8]> for TxHash {
    fn from(id: &[u8]) -> Self {
        Self(id.into())
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
        Ok(from_json(&Binary::from(value)).expect("violated invariant: TxHash is not deserializable"))
    }
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
pub struct XRPLToken {
    pub issuer: XRPLAccountId,
    pub currency: XRPLCurrency,
}

#[cw_serde]
pub enum XRPLPaymentAmount {
    Drops(
        u64,
    ),
    Token(XRPLToken, XRPLTokenAmount),
}

#[cw_serde]
pub enum XRPLSequence {
    Plain(u32),
    Ticket(u32),
}

impl Into<u32> for XRPLSequence {
    fn into(self) -> u32 {
        match self {
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
}

impl XRPLUnsignedTx {
    pub fn sequence(&self) -> &XRPLSequence {
        match self {
            XRPLUnsignedTx::Payment(tx) => {
                &tx.sequence
            },
            XRPLUnsignedTx::TicketCreate(tx) => {
                &tx.sequence
            },
            XRPLUnsignedTx::SignerListSet(tx) => {
                &tx.sequence
            }
        }
    }
    pub fn sequence_number_increment(&self, status: TransactionStatus) -> u32 {
        if status == TransactionStatus::Pending || status == TransactionStatus::Inconclusive {
            return 0;
        }

        match self {
            XRPLUnsignedTx::Payment(tx ) => {
                match tx.sequence {
                    XRPLSequence::Plain(_) => 1,
                    XRPLSequence::Ticket(_) => 0,
                }
            }
            XRPLUnsignedTx::SignerListSet(tx) => {
                match tx.sequence {
                    XRPLSequence::Plain(_) => 1,
                    XRPLSequence::Ticket(_) => 0,
                }
            },
            XRPLUnsignedTx::TicketCreate(tx) => {
                match status {
                    TransactionStatus::Succeeded => tx.ticket_count + 1,
                    TransactionStatus::FailedOnChain => 1,
                    TransactionStatus::Inconclusive |
                    TransactionStatus::Pending => unreachable!(),
                }
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
pub struct XRPLAccountId([u8; 20]);

impl XRPLAccountId {
    pub const fn to_bytes(&self) -> [u8; 20] {
        return self.0;
    }

    pub fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    pub fn to_string(&self) -> String {
        let address_type_prefix: &[u8] = &[0x00];
        let payload = [address_type_prefix, &self.to_bytes()].concat();

        let checksum_hash1 = Sha256::digest(payload.clone());
        let checksum_hash2 = Sha256::digest(checksum_hash1);
        let checksum = &checksum_hash2[0..4];

        bs58::encode([payload, checksum.to_vec()].concat())
            .with_alphabet(bs58::Alphabet::RIPPLE)
            .into_string()
    }
}

impl From<&PublicKey> for XRPLAccountId {
    fn from(pub_key: &PublicKey) -> Self {
        let public_key_hex: HexBinary = pub_key.clone().into();

        assert!(public_key_hex.len() == 33);

        let public_key_inner_hash = Sha256::digest(public_key_hex);
        let account_id = Ripemd160::digest(public_key_inner_hash);

        return XRPLAccountId(account_id.into());
    }
}

impl TryFrom<&str> for XRPLAccountId {
    type Error = ContractError;

    fn try_from(address: &str) -> Result<Self, ContractError> {
        let res = bs58::decode(address).with_alphabet(bs58::Alphabet::RIPPLE).into_vec().map_err(|_| ContractError::InvalidAddress)?;
        // .map_err(|_| ContractError::InvalidAddress)?;
        if res.len() != 25 {
            return Err(ContractError::InvalidAddress);
        }
        let mut buffer = [0u8; 20];
        buffer.copy_from_slice(&res[1..21]);
        return Ok(XRPLAccountId(buffer))
    }
}

#[cw_serde]
pub struct XRPLSigner {
    pub account: XRPLAccountId,
    pub txn_signature: HexBinary,
    pub signing_pub_key: PublicKey,
}

impl TryFrom<(multisig::msg::Signer, multisig::key::Signature)> for XRPLSigner {
    type Error = ContractError;

    fn try_from((axelar_signer, signature): (multisig::msg::Signer, multisig::key::Signature)) -> Result<Self, ContractError> {
        let txn_signature = match signature {
            multisig::key::Signature::Ecdsa(_) |
            multisig::key::Signature::EcdsaRecoverable(_) => HexBinary::from(ecdsa::Signature::to_der(
                &ecdsa::Signature::try_from(signature.clone().as_ref())
                    .map_err(|_| ContractError::FailedToEncodeSignature)?
            ).to_vec()),
            _ => unimplemented!("Unsupported signature type"),
        };

        Ok(XRPLSigner {
            account: XRPLAccountId::from(&axelar_signer.pub_key),
            signing_pub_key: axelar_signer.pub_key.clone().into(),
            txn_signature,
        })
    }
}

#[cw_serde]
pub struct XRPLSignedTransaction {
    pub unsigned_tx: XRPLUnsignedTx,
    pub signers: Vec<XRPLSigner>
}

impl XRPLSignedTransaction {
    pub fn new(unsigned_tx: XRPLUnsignedTx, signers: Vec<XRPLSigner>) -> Self {
        Self { unsigned_tx, signers }
    }
}

#[cw_serde]
pub struct XRPLCurrency(String);

impl XRPLCurrency {
    pub fn to_bytes(self) -> [u8; 20] {
        let mut buffer = [0u8; 20];
        buffer[12..15].copy_from_slice(self.to_string().as_bytes());
        buffer
    }

    // Convert the CurrencyCode to a String
    fn to_string(self) -> String {
        self.0
    }
}

const ALLOWED_CURRENCY_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789?!@#$%^&*<>(){}[]|";

impl TryFrom<String> for XRPLCurrency {
    type Error = ContractError;

    fn try_from(s: String) -> Result<XRPLCurrency, ContractError> {
        if s.len() != 3 || s == "XRP" || !s.chars().all(|c| ALLOWED_CURRENCY_CHARS.contains(c)) {
            return Err(ContractError::InvalidCurrency);
        }
        Ok(XRPLCurrency(s))
    }
}

pub const MIN_MANTISSA: u64 = 1_000_000_000_000_000;
pub const MAX_MANTISSA: u64 = 10_000_000_000_000_000 - 1;
pub const MIN_EXPONENT: i64 = -96;
pub const MAX_EXPONENT: i64 = 80;

// XRPLTokenAmount always in canonicalized XRPL mantissa-exponent format,
// such that MIN_MANTISSA <= mantissa <= MAX_MANTISSA (or equal to zero), MIN_EXPONENT <= exponent <= MAX_EXPONENT,
// In XRPL generally it can be decimal and even negative (!) but in our case that doesn't apply.
#[cw_serde]
pub struct XRPLTokenAmount {
    mantissa: u64,
    exponent: i64
}

impl XRPLTokenAmount {
    pub fn new(mantissa: u64, exponent: i64) -> Self {
        assert!(mantissa == 0 || (MIN_MANTISSA <= mantissa && mantissa <= MAX_MANTISSA && MIN_EXPONENT <= exponent && exponent <= MAX_EXPONENT));
        Self { mantissa, exponent }
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        if self.mantissa == 0 {
            0x8000000000000000u64.to_be_bytes()
        } else {
            // not xrp-bit | positive bit | 8 bits exponent | 54 bits mantissa
            (0xC000000000000000u64 | ((self.exponent + 97) as u64) << 54 | self.mantissa).to_be_bytes()
        }
    }
}

pub fn canonicalize_coin_amount(amount: Uint128, decimals: u8) -> Result<XRPLTokenAmount, ContractError>{
    let (mantissa, exponent) = canonicalize_mantissa(amount, -1 * i64::from(decimals))?;
    Ok(XRPLTokenAmount::new(mantissa, exponent))
}

// always called when XRPLTokenAmount instantiated
// see https://github.com/XRPLF/xrpl-dev-portal/blob/82da0e53a8d6cdf2b94a80594541d868b4d03b94/content/_code-samples/tx-serialization/py/xrpl_num.py#L19
pub fn canonicalize_mantissa(mut mantissa: Uint128, mut exponent: i64) -> Result<(u64, i64), ContractError> {
    let ten = Uint128::from(10u128);

    while mantissa < MIN_MANTISSA.into() && exponent > MIN_EXPONENT {
        mantissa *= ten;
        exponent -= 1;
    }

    while mantissa > MAX_MANTISSA.into() && exponent > MIN_EXPONENT {
        if exponent > MAX_EXPONENT {
            return Err(ContractError::InvalidAmount { reason: "overflow".to_string() });
        }
        mantissa /= ten;
        exponent += 1;
    }

    if exponent < MIN_EXPONENT || mantissa < MIN_MANTISSA.into() {
        return Ok((0, 1));
    }

    if exponent > MAX_EXPONENT || mantissa > MAX_MANTISSA.into() {
        return Err(ContractError::InvalidAmount { reason: format!("overflow exponent {} mantissa {}", exponent, mantissa).to_string() });
    }

    let mantissa = u64::from_be_bytes(mantissa.to_be_bytes()[8..].try_into().unwrap());

    return Ok((mantissa, exponent));
}
