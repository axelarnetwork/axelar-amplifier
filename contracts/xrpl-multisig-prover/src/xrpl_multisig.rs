use std::collections::BTreeSet;


use axelar_wasm_std::{nonempty, FnExt};
use connection_router::state::CrossChainId;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{wasm_execute, HexBinary, Storage, Uint64, WasmMsg};
use multisig::key::PublicKey;
use ripemd::Ripemd160;
use sha2::{Sha512, Digest, Sha256};
use bigdecimal::{BigDecimal, Signed, ToPrimitive, Zero};
use std::str::FromStr;

use crate::{
    error::ContractError,
    state::{Config, LAST_ASSIGNED_TICKET_NUMBER, AVAILABLE_TICKETS, TRANSACTION_INFO, NEXT_SEQUENCE_NUMBER, CONFIRMED_TRANSACTIONS, MESSAGE_ID_TO_TICKET, LATEST_SEQUENTIAL_TX_HASH, NEXT_WORKER_SET, CURRENT_WORKER_SET},
    types::*, axelar_workers::{WorkerSet, AxelarSigner},
};

#[cw_serde]
pub struct XRPLTokenAmount(pub String);

#[cw_serde]
pub enum XRPLPaymentAmount {
    Drops(
        u64,
    ),
    Token(XRPLToken, XRPLTokenAmount),
}

#[cw_serde]
pub enum Sequence {
    Plain(u32),
    Ticket(u32),
}

impl Into<u32> for Sequence {
    fn into(self) -> u32 {
        match self {
            Sequence::Plain(sequence) => sequence,
            Sequence::Ticket(ticket) => ticket,
        }
    }
}

#[cw_serde]
pub struct XRPLSignerEntry {
    pub account: String,
    pub signer_weight: u16,
}

#[cw_serde]
pub enum XRPLUnsignedTx {
    Payment(XRPLPaymentTx),
    SignerListSet(XRPLSignerListSetTx),
    TicketCreate(XRPLTicketCreateTx),
}

impl XRPLUnsignedTx {
    pub fn sequence(&self) -> Sequence {
        match self {
            XRPLUnsignedTx::Payment(tx) => {
                tx.sequence.clone()
            },
            XRPLUnsignedTx::TicketCreate(tx) => {
                tx.sequence.clone()
            },
            XRPLUnsignedTx::SignerListSet(tx) => {
                tx.sequence.clone()
            }
        }
    }
    pub fn sequence_number_increment(&self, status: TransactionStatus) -> u32 {
        if status == TransactionStatus::Pending || status == TransactionStatus::FailedOffChain {
            return 0;
        }

        match self {
            XRPLUnsignedTx::Payment(tx ) => {
                match tx.sequence {
                    Sequence::Plain(_) => 1,
                    Sequence::Ticket(_) => 0,
                }
            }
            XRPLUnsignedTx::SignerListSet(tx) => {
                match tx.sequence {
                    Sequence::Plain(_) => 1,
                    Sequence::Ticket(_) => 0,
                }
            },
            XRPLUnsignedTx::TicketCreate(tx) => {
                match status {
                    TransactionStatus::Succeeded => tx.ticket_count + 1,
                    TransactionStatus::FailedOnChain => 1,
                    TransactionStatus::FailedOffChain |
                    TransactionStatus::Pending => unreachable!(),
                }
            },
        }
    }
}

impl TryFrom<&XRPLUnsignedTx> for XRPLObject {
    type Error = ContractError;

    fn try_from(tx: &XRPLUnsignedTx) -> Result<Self, ContractError> {
        match tx {
            XRPLUnsignedTx::Payment(tx) => tx.try_into(),
            XRPLUnsignedTx::TicketCreate(tx) => tx.try_into(),
            XRPLUnsignedTx::SignerListSet(tx) => tx.try_into()
        }
    }
}

pub struct XRPLMemo(HexBinary);

impl TryFrom<&XRPLMemo> for XRPLObject {
    type Error = ContractError;

    fn try_from(memo: &XRPLMemo) -> Result<Self, ContractError> {
        println!("memo contents hex {}", hex::encode(memo.0.clone()));
        let mut obj = XRPLObject::new();
        obj.add_field(13, &memo.0)?;
        Ok(obj)
    }
}

impl XRPLSerialize for XRPLMemo {
    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError> {
        let mut obj = XRPLObject::new();
        obj.add_field(13, &self.0)?;
        let mut result = obj.xrpl_serialize()?;
        result.extend(field_id(OBJECT_TYPE_CODE, 1));
        Ok(result)
 
    }
}

impl XRPLTypedSerialize for XRPLMemo {
    const TYPE_CODE: u8 = OBJECT_TYPE_CODE;
}

#[cw_serde]
pub struct XRPLPaymentTx {
    pub account: String,
    pub fee: u64,
    pub sequence: Sequence,
    pub amount: XRPLPaymentAmount,
    pub destination: nonempty::String,
    pub multisig_session_id: Option<Uint64>
}

impl TryFrom<&XRPLPaymentTx> for XRPLObject {
    type Error = ContractError;

    fn try_from(tx: &XRPLPaymentTx) -> Result<Self, ContractError> {
        let mut obj = XRPLObject::new();
        obj.add_field(2, &PAYMENT_TX_TYPE)?;
        obj.add_field(2, &0u32)?; // flags
        add_sequence(&mut obj, &tx.sequence)?;
        // type: Amount, type_code: 6, nth: 1, !isVLEncoded
        obj.add_field(1, &tx.amount)?;
        // type: Amount, type_code: 6, nth: 8, !isVLEncoded
        obj.add_field(8, &XRPLPaymentAmount::Drops(tx.fee))?;
        obj.add_field(3, &HexBinary::from_hex("")?)?;
        obj.add_field(1, &XRPLAddress(tx.account.clone()))?;
        obj.add_field(3, &XRPLAddress(tx.destination.to_string()))?;

        if let Some(multisig_session_id) = tx.multisig_session_id {
            let memo_data: Vec<u8> = multisig_session_id.to_be_bytes().iter().skip_while(|&&byte| byte == 0).cloned().collect();
            let memo = HexBinary::from_hex(hex::encode(memo_data).as_ref())?;
            obj.add_field(9, &XRPLArray{field_code: 10, items: vec![XRPLMemo(memo)]})?;
        }

        Ok(obj)
    }
}

#[cw_serde]
pub struct XRPLSignerListSetTx {
    pub account: String,
    pub fee: u64,
    pub sequence: Sequence,
    pub signer_quorum: u32,
    pub signer_entries: Vec<XRPLSignerEntry>,
    pub multisig_session_id: Option<Uint64>
}

impl TryFrom<&XRPLSignerListSetTx> for XRPLObject {
    type Error = ContractError;

    fn try_from(tx: &XRPLSignerListSetTx) -> Result<Self, ContractError> {
        let mut obj = XRPLObject::new();

        obj.add_field(2, &SIGNER_LIST_SET_TX_TYPE)?;
        obj.add_field(2, &0u32)?; // flags
        add_sequence(&mut obj, &tx.sequence)?;
        obj.add_field(35, &tx.signer_quorum)?;
        obj.add_field(8, &XRPLPaymentAmount::Drops(tx.fee))?;
        obj.add_field(1, &XRPLAddress(tx.account.clone()))?;
        obj.add_field(3, &HexBinary::from_hex("")?)?;

        obj.add_field(4, &XRPLArray{ field_code: 11, items: tx.signer_entries.clone() })?;

        if let Some(multisig_session_id) = tx.multisig_session_id {
            let memo_data: Vec<u8> = multisig_session_id.to_be_bytes().iter().skip_while(|&&byte| byte == 0).cloned().collect();
            let memo = HexBinary::from_hex(hex::encode(memo_data).as_ref())?;
            obj.add_field(9, &XRPLArray{field_code: 10, items: vec![XRPLMemo(memo)]})?;
        }

        Ok(obj)
    }
}


#[cw_serde]
pub struct XRPLTicketCreateTx {
    pub account: String,
    pub fee: u64,
    pub sequence: Sequence,
    pub ticket_count: u32,
    pub multisig_session_id: Option<Uint64>
}

impl TryFrom<&XRPLTicketCreateTx> for XRPLObject {
    type Error = ContractError;

    fn try_from(tx: &XRPLTicketCreateTx) -> Result<Self, ContractError> {
        let mut obj = XRPLObject::new();
        // type_code: 1,  nth: 2, !isVLEncoded
        obj.add_field(2, &TICKET_CREATE_TX_TYPE)?;
        obj.add_field(2, &0u32)?; // flags
        add_sequence(&mut obj, &tx.sequence)?;
        obj.add_field(40, &tx.ticket_count)?; // 202800000000a
        obj.add_field(8, &XRPLPaymentAmount::Drops(tx.fee))?; // 68400000000000001e
        obj.add_field(3, &HexBinary::from_hex("")?)?;
        obj.add_field(1, &XRPLAddress(tx.account.clone()))?;

        if let Some(multisig_session_id) = tx.multisig_session_id {
            let memo_data: Vec<u8> = multisig_session_id.to_be_bytes().iter().skip_while(|&&byte| byte == 0).cloned().collect();
            let memo = HexBinary::from_hex(hex::encode(memo_data).as_ref())?;
            obj.add_field(9, &XRPLArray{field_code: 10, items: vec![XRPLMemo(memo)]})?;
        }

        Ok(obj)
    }
}

#[cw_serde]
pub struct XRPLSigner {
    pub account: String,
    pub txn_signature: HexBinary,
    pub signing_pub_key: PublicKey,
}

#[cw_serde]
pub struct XRPLSignedTransaction {
    pub unsigned_tx: XRPLUnsignedTx,
    pub signers: Vec<XRPLSigner>
}

pub fn get_next_ticket_number(storage: &dyn Storage) -> Result<u32, ContractError> {
    let last_assigned_ticket_number: u32 = LAST_ASSIGNED_TICKET_NUMBER.load(storage)?;
    // TODO: handle no available tickets
    let available_tickets = AVAILABLE_TICKETS.load(storage)?;

    // find next largest in available, otherwise use available_tickets[0]
    // TODO: handle IndexOutOfBounds error on available_tickets[0]
    let ticket_number = available_tickets.iter().find(|&x| x > &last_assigned_ticket_number).unwrap_or(&available_tickets[0]);
    Ok(*ticket_number)
}

pub fn available_ticket_count(storage: &mut dyn Storage) -> Result<u32, ContractError> {
    let available_tickets = AVAILABLE_TICKETS.load(storage)?;
    let ticket_count = 250 - (available_tickets.len() as u32);
    Ok(ticket_count)
}

const PAYMENT_TX_TYPE: u16 = 0;
const TICKET_CREATE_TX_TYPE: u16 = 10;
const SIGNER_LIST_SET_TX_TYPE: u16 = 12;

const UINT16_TYPE_CODE: u8 = 1;
const UINT32_TYPE_CODE: u8 = 2;
const AMOUNT_TYPE_CODE: u8 = 6;
const BLOB_TYPE_CODE: u8 = 7;
const ACCOUNT_ID_TYPE_CODE: u8 = 8;
const OBJECT_TYPE_CODE: u8 = 14;
const ARRAY_TYPE_CODE: u8 = 15;

// field ids and type codes from here
// https://github.com/XRPLF/xrpl.js/blob/main/packages/ripple-binary-codec/src/enums/definitions.json
pub fn field_id(type_code: u8, field_code: u8) -> Vec<u8> {
    assert!(type_code < 16);
    if field_code < 16 {
        vec![type_code << 4 | field_code]
    } else {
        vec![type_code << 4, field_code]
    }
}

const POSITIVE_BIT: u64 = 0x4000000000000000;

const MIN_MANTISSA: u64 = 1_000_000_000_000_000;
const MAX_MANTISSA: u64 = 10_000_000_000_000_000 - 1;
const MIN_EXPONENT: i64 = -96;
const MAX_EXPONENT: i64 = 80;


// see https://github.com/XRPLF/xrpl-dev-portal/blob/82da0e53a8d6cdf2b94a80594541d868b4d03b94/content/_code-samples/tx-serialization/py/xrpl_num.py#L19
pub fn amount_to_bytes(amount: &XRPLTokenAmount) -> Result<Vec<u8>, ContractError> {
    let decimal = BigDecimal::from_str(amount.0.trim()).map_err(|e| { ContractError::InvalidAmount { amount: amount.clone().0, reason: e.to_string() } })?;

    let is_negative = decimal.is_negative();

    let mut serial: u64 = 0x8000000000000000;
    if decimal.is_zero() {
        return Ok(Vec::from(serial.to_be_bytes()))
    }

    let (mut mantissa, mut exponent) = decimal.into_bigint_and_exponent().then(|(m, e)| (m.abs().to_biguint().unwrap(), e * -1));

    while mantissa < MIN_MANTISSA.into() && exponent > MIN_EXPONENT {
        mantissa *= 10u8;
        exponent -= 1;
    }

    while mantissa > MAX_MANTISSA.into() && exponent > MIN_EXPONENT {
        if exponent > MAX_EXPONENT {
            return Err(ContractError::InvalidAmount { amount: amount.clone().0, reason: "overflow 1".to_string() });
        }
        mantissa /= 10u8;
        exponent += 1;
    }

    if exponent < MIN_EXPONENT || mantissa < MIN_MANTISSA.into() {
        return Ok(Vec::from(serial.to_be_bytes()));
    }

    if exponent > MAX_EXPONENT || mantissa > MAX_MANTISSA.into() {
        return Err(ContractError::InvalidAmount { amount: amount.clone().0, reason: format!("overflow exponent {} mantissa {}", exponent, mantissa).to_string() });
    }

    if !is_negative {
        serial |= 0x4000000000000000; // set positive bit
    }

    serial |= ((exponent+97) as u64) << 54; // next 8 bits are exponent

    serial |= mantissa.to_u64().unwrap(); // last 54 bits are mantissa

    Ok(Vec::from(serial.to_be_bytes()))
}


pub fn currency_to_bytes(currency: &String) -> Result<[u8; 20], ContractError> {
    if currency.len() != 3 || !currency.is_ascii() || currency == "XRP" {
        return Err(ContractError::InvalidCurrency);
    }
    let mut buffer = [0u8; 20];
    buffer[12..15].copy_from_slice(currency.as_bytes());
    Ok(buffer)
}

pub fn decode_address(address: &String) -> Result<[u8; 20], ContractError> {
    let res = bs58::decode(address).with_alphabet(bs58::Alphabet::RIPPLE).into_vec().unwrap();
    // .map_err(|_| ContractError::InvalidAddress)?;
    if res.len() != 25 {
        return Err(ContractError::InvalidAddress);
    }
    let mut buffer = [0u8; 20];
    buffer.copy_from_slice(&res[1..21]);
    return Ok(buffer)
}

pub const HASH_PREFIX_SIGNED_TRANSACTION: [u8; 4] = [0x54, 0x58, 0x4E, 0x00];

pub fn compute_unsigned_tx_hash(unsigned_tx: &XRPLUnsignedTx) -> Result<TxHash, ContractError> {
    let encoded_unsigned_tx = serde_json::to_vec(unsigned_tx).map_err(|_| ContractError::FailedToSerialize)?;

    let d = Sha256::digest(encoded_unsigned_tx);
    let tx_hash_hex: HexBinary = HexBinary::from(d.to_vec());
    let tx_hash: TxHash = TxHash(tx_hash_hex.clone());
    Ok(tx_hash)
}

pub fn compute_signed_tx_hash(encoded_signed_tx: Vec<u8>) -> Result<TxHash, ContractError> {
    let tx_hash_hex: HexBinary = HexBinary::from(xrpl_hash(Some(HASH_PREFIX_SIGNED_TRANSACTION), encoded_signed_tx.as_slice()));
    let tx_hash: TxHash = TxHash(tx_hash_hex.clone());
    Ok(tx_hash)
}

pub struct XRPLAddress(String);

pub trait XRPLSerialize {
    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError>;
}

pub trait XRPLTypedSerialize: XRPLSerialize {
    const TYPE_CODE: u8;
}

impl XRPLSerialize for u16 {
    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError> {
        Ok(self.to_be_bytes().to_vec())
    }
}

impl XRPLTypedSerialize for u16 {
    const TYPE_CODE: u8 = UINT16_TYPE_CODE;
}

impl XRPLSerialize for u32 {
    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError> {
        Ok(self.to_be_bytes().to_vec())
    }
}

impl XRPLTypedSerialize for u32 {
    const TYPE_CODE: u8 = UINT32_TYPE_CODE;
}

impl XRPLSerialize for XRPLPaymentAmount {
    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError> {
        match self {
            XRPLPaymentAmount::Drops(value) => {
                if *value <= 10u64.pow(17) {
                    Ok((value | POSITIVE_BIT).to_be_bytes().to_vec())
                } else {
                    Err(ContractError::InvalidAmount { reason: "more than maximum amount of drops".to_string(), amount: value.to_string() })
                }
            },
            XRPLPaymentAmount::Token(token, amount) => {
                let mut result = Vec::new();
                result.extend(amount_to_bytes(amount)?);
                result.extend(currency_to_bytes(&token.currency)?);
                result.extend(decode_address(&token.issuer)?);
                Ok(result)
            }
        }
    }
}

impl XRPLTypedSerialize for XRPLPaymentAmount {
    const TYPE_CODE: u8 = AMOUNT_TYPE_CODE;
}

impl XRPLSerialize for XRPLSignedTransaction {
    fn xrpl_serialize(self: &XRPLSignedTransaction) -> Result<Vec<u8>, ContractError> {
        let mut sorted_signers = self.signers.clone();
        sorted_signers.sort_by(|a, b| {
            // the Signers array must be sorted based on the numeric value of the signer addresses
            // https://xrpl.org/multi-signing.html#sending-multi-signed-transactions
            let a = bs58::decode(a.account.clone()).with_alphabet(bs58::Alphabet::RIPPLE).into_vec().unwrap();
            let b = bs58::decode(b.account.clone()).with_alphabet(bs58::Alphabet::RIPPLE).into_vec().unwrap();
            return a.cmp(&b);
        });
        let mut obj = XRPLObject::try_from(&self.unsigned_tx)?;
        obj.add_field(3, &XRPLArray{ field_code: 16, items: sorted_signers })?;

        obj.xrpl_serialize()
    }
}

impl XRPLSerialize for XRPLUnsignedTx {
    fn xrpl_serialize(self: &XRPLUnsignedTx) -> Result<Vec<u8>, ContractError> {
        let obj = XRPLObject::try_from(self)?;

        let mut result = Vec::from((0x534D5400 as u32).to_be_bytes()); // prefix for multisignature signing
        result.extend(obj.xrpl_serialize()?);
        Ok(result)
    }
}

struct XRPLArray<T> {
    field_code: u8,
    items: Vec<T>
}

impl<T: XRPLTypedSerialize> XRPLSerialize for XRPLArray<T> {
    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError> {
        let mut result: Vec<u8> = Vec::new();
        for item in &self.items {
            result.extend(field_id(T::TYPE_CODE, self.field_code));
            result.extend(item.xrpl_serialize()?);
        }
        result.extend(field_id(ARRAY_TYPE_CODE, 1));
        Ok(result)
    }
}

impl<T: XRPLTypedSerialize> XRPLTypedSerialize for XRPLArray<T> {
    const TYPE_CODE: u8 = ARRAY_TYPE_CODE;
}


// see https://github.com/XRPLF/xrpl-dev-portal/blob/master/content/_code-samples/tx-serialization/py/serialize.py#L92
// returns None if length too big
pub fn encode_length(mut length: usize) -> Option<Vec<u8>> {
    if length <= 192 {
        return Some(vec![length as u8]);
    } else if length <= 12480 {
        length -= 193;
        return Some(vec![193 + (length >> 8) as u8, (length & 0xff) as u8]);
    } else if length <= 918744  {
        length -= 12481;
        return Some(vec![
            241 + (length >> 16) as u8,
            ((length >> 8) & 0xff) as u8,
            (length & 0xff) as u8
        ])
    } else {
        return None
    }
}

impl XRPLSerialize for HexBinary {
    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError> {
        match encode_length(self.len()) {
            Some(encoded_length) => {
                let mut result = Vec::new();
                result.extend(encoded_length);
                result.extend(self.to_vec());
                Ok(result)
            }
            None => Err(ContractError::InvalidBlob)
        }
    }
}

impl XRPLTypedSerialize for HexBinary {
    const TYPE_CODE: u8 = BLOB_TYPE_CODE;
}

impl XRPLSerialize for PublicKey {
    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError> {
        match self.clone() {
            // rippled prefixes Ed25519 public keys with the byte 0xED so both types of public key are 33 bytes.
            // https://xrpl.org/cryptographic-keys.html
            Self::Ed25519(hex) => HexBinary::from_hex(format!("ED{}", hex.to_hex()).as_str())?.xrpl_serialize(),
            Self::Ecdsa(hex) => hex.xrpl_serialize(),
        }
    }
}

impl XRPLTypedSerialize for PublicKey {
    const TYPE_CODE: u8 = BLOB_TYPE_CODE;
}

impl XRPLSerialize for XRPLSigner {
    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError> {
        let mut obj = XRPLObject::new();
        obj.add_field(3, &self.signing_pub_key)?;
        obj.add_field(4, &self.txn_signature)?;
        obj.add_field(1, &XRPLAddress(self.account.clone()))?;
        let mut result = obj.xrpl_serialize()?;
        result.extend(field_id(OBJECT_TYPE_CODE, 1));
        Ok(result)
    }
}

impl XRPLTypedSerialize for XRPLSigner {
    const TYPE_CODE: u8 = OBJECT_TYPE_CODE;
}

impl XRPLSerialize for XRPLAddress {
    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError> {
        let mut result: Vec<u8> = Vec::new();
        result.extend(vec![20]); // 0x14, length-encoding
        result.extend(decode_address(&self.0)?);
        Ok(result)
    }
}

impl XRPLTypedSerialize for XRPLAddress {
    const TYPE_CODE: u8 = ACCOUNT_ID_TYPE_CODE;
}


impl XRPLSerialize for XRPLSignerEntry {
    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError> {
        let mut obj = XRPLObject::new();
        obj.add_field(1, &XRPLAddress(self.account.clone()))?;
        obj.add_field(3, &self.signer_weight)?;
        let mut result = obj.xrpl_serialize()?;
        result.extend(field_id(OBJECT_TYPE_CODE, 1));
        Ok(result)
    }
}

impl XRPLTypedSerialize for XRPLSignerEntry {
    const TYPE_CODE: u8 = OBJECT_TYPE_CODE;
}


#[derive(Debug, Clone)]
pub struct XRPLObject {
    fields: Vec<(u8, u8, Vec<u8>)>
}

impl XRPLObject {
    pub fn new() -> XRPLObject {
        Self {
            fields: Vec::new()
        }
    }

    pub fn add_field<T: XRPLTypedSerialize>(&mut self, field_code: u8, value: &T) -> Result<(), ContractError> {
        self.fields.push((T::TYPE_CODE, field_code, value.xrpl_serialize()?));
        Ok(())
    }
}

pub fn add_sequence(obj: &mut XRPLObject, sequence: &Sequence) -> Result<(), ContractError> {
    match sequence {
        Sequence::Plain(seq) => {
            obj.add_field(4, seq)
        },
        Sequence::Ticket(seq) => {
            obj.add_field(4, &0u32)?;
            obj.add_field(41, seq)
        }
    }
}

impl XRPLSerialize for XRPLObject {
    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError> {
        let mut tmp: Vec<(u8, u8, Vec<u8>)> = self.fields.clone();
        tmp.sort_by(|a, b| { (a.0, a.1).cmp(&(b.0, b.1)) });
        let res = tmp.into_iter()
            .map(|f| {
                let mut res = Vec::new();
                res.extend(field_id(f.0, f.1));
                res.extend(f.2);
                return res;
            })
            .collect::<Vec<Vec<u8>>>()
            .concat();
        Ok(res)
    }
}

// TODO: impl XRPLSerialize for all types implementing Into<XRPLObject>

// TODO: fix to not take prefix as param
pub fn xrpl_hash(
    prefix: Option<[u8; 4]>,
    tx_blob: &[u8],
) -> [u8; 32] {
    let mut hasher = match prefix {
        Some(prefix) => Sha512::new_with_prefix(prefix),
        None => Sha512::new(),
    };
    hasher.update(tx_blob);
    let hash: [u8; 64] = hasher.finalize().into();
    let mut half_hash: [u8; 32] = [0; 32];
    half_hash.copy_from_slice(&hash[..32]);
    half_hash
}

fn issue_tx(
    storage: &mut dyn Storage,
    tx: XRPLUnsignedTx,
    message_id: Option<CrossChainId>,
) -> Result<TxHash, ContractError> {
    let tx_hash = compute_unsigned_tx_hash(&tx)?;

    TRANSACTION_INFO.save(
        storage,
        tx_hash.clone(),
        &TransactionInfo {
            status: TransactionStatus::Pending,
            unsigned_contents: tx.clone(),
            message_id,
        }
    )?;

    match tx.sequence() {
        Sequence::Ticket(ticket_number) => {
            LAST_ASSIGNED_TICKET_NUMBER.save(storage, &ticket_number)?;
        },
        Sequence::Plain(_) => {
            LATEST_SEQUENTIAL_TX_HASH.save(storage, &tx_hash)?;
        },
    };

    Ok(tx_hash)
}

pub fn issue_payment(
    storage: &mut dyn Storage,
    config: &Config,
    destination: nonempty::String,
    amount: XRPLPaymentAmount,
    message_id: CrossChainId,
) -> Result<TxHash, ContractError> {
    let ticket_number = assign_ticket_number(storage, message_id.clone())?;

    let tx = XRPLPaymentTx {
        account: config.xrpl_multisig_address.to_string(),
        fee: config.xrpl_fee,
        sequence: Sequence::Ticket(ticket_number),
        multisig_session_id: None,
        amount,
        destination
    };

    issue_tx(
        storage,
        XRPLUnsignedTx::Payment(tx),
        Some(message_id),
    )
}

pub fn issue_ticket_create(storage: &mut dyn Storage, config: &Config, ticket_count: u32) -> Result<TxHash, ContractError> {
    let sequence_number = get_next_sequence_number(storage)?;

    let tx = XRPLTicketCreateTx {
        account: config.xrpl_multisig_address.to_string(),
        fee: config.xrpl_fee,
        sequence: Sequence::Plain(sequence_number.clone()),
        ticket_count,
        multisig_session_id: None
    };

    issue_tx(
        storage,
        XRPLUnsignedTx::TicketCreate(tx),
        None,
    )
}

pub fn issue_signer_list_set(storage: &mut dyn Storage, config: &Config, workers: WorkerSet) -> Result<TxHash, ContractError> {
    let sequence_number = get_next_sequence_number(storage)?;

    let tx = XRPLSignerListSetTx {
        account: config.xrpl_multisig_address.to_string(),
        fee: config.xrpl_fee,
        sequence: Sequence::Plain(sequence_number.clone()),
        signer_quorum: workers.quorum,
        signer_entries: make_xrpl_signer_entries(workers.signers),
        multisig_session_id: None
    };

    issue_tx(
        storage,
        XRPLUnsignedTx::SignerListSet(tx),
        None,
    )
}

fn make_xrpl_signer_entries(signers: BTreeSet<AxelarSigner>) -> Vec<XRPLSignerEntry> {
    signers
        .into_iter()
        .map(
            |worker| {
                XRPLSignerEntry {
                    account: public_key_to_xrpl_address(worker.pub_key),
                    signer_weight: worker.weight,
                }
            }
        ).collect()
}

pub fn public_key_to_xrpl_address(public_key: multisig::key::PublicKey) -> String {
    let public_key_hex: HexBinary = public_key.into();

    assert!(public_key_hex.len() == 33);

    let public_key_inner_hash = Sha256::digest(public_key_hex);
    let account_id = Ripemd160::digest(public_key_inner_hash);
    return account_id_bytes_to_address(&account_id);
}

pub fn account_id_bytes_to_address(account_id: &[u8]) -> String {
    let address_type_prefix: &[u8] = &[0x00];
    let payload = [address_type_prefix, &account_id].concat();

    let checksum_hash1 = Sha256::digest(payload.clone());
    let checksum_hash2 = Sha256::digest(checksum_hash1);
    let checksum = &checksum_hash2[0..4];

    bs58::encode([payload, checksum.to_vec()].concat())
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_string()
}


fn get_next_sequence_number(storage: &dyn Storage) -> Result<u32, ContractError> {
    match load_latest_sequential_tx_info(storage)? {
        Some(latest_sequential_tx_info) if latest_sequential_tx_info.status == TransactionStatus::Pending => {
            Ok(latest_sequential_tx_info.unsigned_contents.sequence().into())
        },
        _ => NEXT_SEQUENCE_NUMBER.load(storage).map_err(|e| e.into())
    }
}

fn load_latest_sequential_tx_info(
    storage: &dyn Storage,
) -> Result<Option<TransactionInfo>, ContractError> {
    let latest_sequential_tx_hash = LATEST_SEQUENTIAL_TX_HASH.may_load(storage)?;
    if latest_sequential_tx_hash.is_none() {
        return Ok(None)
    }

    Ok(TRANSACTION_INFO.may_load(storage, latest_sequential_tx_hash.unwrap())?)
}

fn mark_tickets_available(storage: &mut dyn Storage, tickets: impl Iterator<Item = u32>) -> Result<(), ContractError> {
    AVAILABLE_TICKETS.update(storage, |available_tickets| -> Result<_, ContractError> {
        let mut new_available_tickets = available_tickets.clone();
        for i in tickets {
            new_available_tickets.push(i);
        }

        Ok(new_available_tickets)
    })?;
    Ok(())
}

fn mark_ticket_unavailable(storage: &mut dyn Storage, ticket: u32) -> Result<(), ContractError> {
    AVAILABLE_TICKETS.update(storage, |available_tickets| -> Result<_, ContractError> {
        Ok(available_tickets
            .into_iter()
            .filter(|&x| x != ticket)
            .collect())
    })?;
    Ok(())
}

pub fn update_tx_status(
    storage: &mut dyn Storage,
    axelar_multisig_address: impl Into<String>,
    unsigned_tx_hash: TxHash,
    new_status: TransactionStatus
) -> Result<Option<WasmMsg>, ContractError> {
    let mut tx_info = TRANSACTION_INFO.load(storage, unsigned_tx_hash.clone())?;
    if tx_info.status != TransactionStatus::Pending {
        return Err(ContractError::TransactionStatusAlreadyUpdated);
    }

    tx_info.status = new_status.clone();

    let tx_sequence_number: u32 = tx_info.unsigned_contents.sequence().clone().into();

    let sequence_number_increment = tx_info.unsigned_contents.sequence_number_increment(new_status.clone());
    if sequence_number_increment > 0 && tx_sequence_number == NEXT_SEQUENCE_NUMBER.load(storage)? {
        NEXT_SEQUENCE_NUMBER.save(storage, &(tx_sequence_number + sequence_number_increment))?;
    }

    if new_status == TransactionStatus::Succeeded || new_status == TransactionStatus::FailedOnChain {
        CONFIRMED_TRANSACTIONS.save(storage, tx_sequence_number, &unsigned_tx_hash)?;
        mark_ticket_unavailable(storage, tx_sequence_number)?;
    }

    TRANSACTION_INFO.save(storage, unsigned_tx_hash.clone(), &tx_info)?;

    if tx_info.status != TransactionStatus::Succeeded {
        return Ok(None);
    }

    let res = match tx_info.unsigned_contents.clone() {
        XRPLUnsignedTx::TicketCreate(tx) => {
            mark_tickets_available(
                storage,
                (tx_sequence_number + 1)..(tx_sequence_number + tx.ticket_count),
            )?;
            None
        },
        XRPLUnsignedTx::SignerListSet(_tx) => {
            let next_worker_set = NEXT_WORKER_SET.load(storage, unsigned_tx_hash.clone())?;
            CURRENT_WORKER_SET.save(storage, &next_worker_set)?;
            NEXT_WORKER_SET.remove(storage, unsigned_tx_hash);

            let msg = wasm_execute(
                axelar_multisig_address,
                &multisig::msg::ExecuteMsg::RegisterWorkerSet {
                    worker_set: next_worker_set.into(),
                },
                vec![],
            )?;
            Some(msg)
        },
        XRPLUnsignedTx::Payment(_) => None
    };

    Ok(res)
}

// A message ID can be ticketed a different ticket number
// only if the previous ticket number has been consumed
// by a TX that doesn't correspond to this message.
pub fn assign_ticket_number(storage: &mut dyn Storage, message_id: CrossChainId) -> Result<u32, ContractError> {
    // If this message ID has already been ticketed,
    // then use the same ticket number as before,
    if let Some(ticket_number) = MESSAGE_ID_TO_TICKET.may_load(storage, message_id.clone())? {
        // as long as it has not already been consumed
        let confirmed_tx_hash = CONFIRMED_TRANSACTIONS.may_load(storage, ticket_number)?;
        if confirmed_tx_hash.is_none() {
            return Ok(ticket_number)
        }

        // or if it has been consumed by the same message.
        let tx_info = TRANSACTION_INFO.load(storage, confirmed_tx_hash.unwrap())?;
        if tx_info.message_id.map_or(false, |id| id == message_id) {
            return Ok(ticket_number)
        }
    }

    // Otherwise, use the next available ticket number.
    let new_ticket_number = get_next_ticket_number(storage)?;
    MESSAGE_ID_TO_TICKET.save(storage, message_id, &new_ticket_number)?;
    Ok(new_ticket_number)
}

#[cfg(test)]
mod tests {
    use multisig::key::{KeyType, PublicKey};

    use super::*;

    #[macro_export]
    macro_rules! assert_hex_eq {
        ($expected:expr, $actual:expr) => {
            assert_eq!($expected, hex::encode_upper($actual));
        };
    }

    #[test]
    fn test_encode_length() {
        assert_hex_eq!("00", encode_length(0).unwrap());
        assert_hex_eq!("0A", encode_length(10).unwrap());
        assert_hex_eq!("C100", encode_length(193).unwrap());
        assert_hex_eq!("F10000", encode_length(12481).unwrap());
        assert_hex_eq!("FED417", encode_length(918744).unwrap());
        assert_eq!(None, encode_length(918745));
    }

    #[test]
    fn test_account_id_to_bytes_address() {
        assert_eq!("rrrrrrrrrrrrrrrrrrrrrhoLvTp", account_id_bytes_to_address(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!("rQLbzfJH5BT1FS9apRLKV3G8dWEA5njaQi", account_id_bytes_to_address(&[255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]));
    }

    #[test]
    fn test_xrpl_serialize() -> Result<(), ContractError> {
        assert_hex_eq!("0000", 0u16.xrpl_serialize()?);
        assert_hex_eq!("0001", 1u16.xrpl_serialize()?);
        assert_hex_eq!("FFFF", 0xffffu16.xrpl_serialize()?);
        assert_hex_eq!("00000000", 0u32.xrpl_serialize()?);
        assert_hex_eq!("00000005", 5u32.xrpl_serialize()?);
        assert_hex_eq!("FFFFFFFF", 0xffffffffu32.xrpl_serialize()?);
        assert_hex_eq!("00", HexBinary::from_hex("").unwrap().xrpl_serialize()?);
        assert_hex_eq!("04DEADBEEF", HexBinary::from_hex("DEADBEEF").unwrap().xrpl_serialize()?);
        assert_hex_eq!(
            "800000000000000000000000000000000000000055534400000000005B812C9D57731E27A2DA8B1830195F88EF32A3B6",
            XRPLPaymentAmount::Token(XRPLToken {
                issuer: "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ".to_string(),
                currency: "USD".to_string(),
            }, XRPLTokenAmount("0".to_string()))
            .xrpl_serialize()?
        );
        assert_hex_eq!(
            "D4838D7EA4C6800000000000000000000000000055534400000000005B812C9D57731E27A2DA8B1830195F88EF32A3B6",
            XRPLPaymentAmount::Token(XRPLToken {
                issuer: "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ".to_string(),
                currency: "USD".to_string(),
            }, XRPLTokenAmount("1".to_string()))
            .xrpl_serialize()?
        );
        // minimum amount
        assert_hex_eq!(
            "AC6386F26FC0FFFF00000000000000000000000055534400000000005B812C9D57731E27A2DA8B1830195F88EF32A3B6",
            XRPLPaymentAmount::Token(XRPLToken {
                issuer: "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ".to_string(),
                currency: "USD".to_string(),
            }, XRPLTokenAmount("-9999999999999999e80".to_string()))
            .xrpl_serialize()?
        );
        // less than minimum amount fails
        assert!(
            XRPLPaymentAmount::Token(XRPLToken {
                issuer: "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ".to_string(),
                currency: "USD".to_string(),
            }, XRPLTokenAmount("-10000000000000000e80".to_string()))
            .xrpl_serialize()
            .is_err()
        );
        // minimum absolute amount
        assert_hex_eq!(
            "C0438D7EA4C6800000000000000000000000000055534400000000005B812C9D57731E27A2DA8B1830195F88EF32A3B6",
            XRPLPaymentAmount::Token(XRPLToken {
                issuer: "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ".to_string(),
                currency: "USD".to_string(),
            }, XRPLTokenAmount("1000000000000000e-96".to_string()))
            .xrpl_serialize()?
        );
        // less than minimum absolute positive amount serializes to 0
        assert_hex_eq!(
            "800000000000000000000000000000000000000055534400000000005B812C9D57731E27A2DA8B1830195F88EF32A3B6",
            XRPLPaymentAmount::Token(XRPLToken {
                issuer: "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ".to_string(),
                currency: "USD".to_string(),
            }, XRPLTokenAmount("999999999999999e-96".to_string()))
            .xrpl_serialize()?
        );
        // less than minimum absolute negative amount serializes to 0
        assert_hex_eq!(
            "800000000000000000000000000000000000000055534400000000005B812C9D57731E27A2DA8B1830195F88EF32A3B6",
            XRPLPaymentAmount::Token(XRPLToken {
                issuer: "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ".to_string(),
                currency: "USD".to_string(),
            }, XRPLTokenAmount("-999999999999999e-96".to_string()))
            .xrpl_serialize()?
        );
        // maximum amount
        assert_hex_eq!(
            "EC6386F26FC0FFFF00000000000000000000000055534400000000005B812C9D57731E27A2DA8B1830195F88EF32A3B6",
            XRPLPaymentAmount::Token(XRPLToken {
                issuer: "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ".to_string(),
                currency: "USD".to_string(),
            }, XRPLTokenAmount("9999999999999999e80".to_string()))
            .xrpl_serialize()?
        );
        // more than maximum amount fails
        assert!(
            XRPLPaymentAmount::Token(XRPLToken {
                issuer: "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ".to_string(),
                currency: "USD".to_string(),
            }, XRPLTokenAmount("10000000000000000e80".to_string()))
            .xrpl_serialize()
            .is_err()
        );
        // test integer and fractional part with zeroes
        assert_hex_eq!(
            "D58462510B02ED1500000000000000000000000055534400000000005B812C9D57731E27A2DA8B1830195F88EF32A3B6",
            XRPLPaymentAmount::Token(XRPLToken {
                issuer: "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ".to_string(),
                currency: "USD".to_string(),
            }, XRPLTokenAmount("0012340.0012345678900".to_string()))
            .xrpl_serialize()?
        );
        // currency can contain non-alphanumeric ascii letters
        assert_hex_eq!(
            "D4CEEBE0B40E8000000000000000000000000000247B3B00000000005B812C9D57731E27A2DA8B1830195F88EF32A3B6",
            XRPLPaymentAmount::Token(XRPLToken {
                issuer: "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ".to_string(),
                currency: "${;".to_string(),
            }, XRPLTokenAmount("42".to_string()))
            .xrpl_serialize()?
        );
        // TODO: these could be enforced on a type level:
        //   - currency cannot contain non-ascii letters
        //   - currency must not be more than 3 ascii letters
        //   - currency must not be less than 3 ascii letters
        // XRP currency code is not allowed
        assert!(
            XRPLPaymentAmount::Token(XRPLToken {
                issuer: "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ".to_string(),
                currency: "XRP".to_string(),
            }, XRPLTokenAmount("42".to_string()))
            .xrpl_serialize()
            .is_err()
        );
        // minimum XRP
        assert_hex_eq!(
            "4000000000000000",
            XRPLPaymentAmount::Drops(0)
            .xrpl_serialize()?
        );
        assert_hex_eq!(
            "4000000000000001",
            XRPLPaymentAmount::Drops(1)
            .xrpl_serialize()?
        );
        assert_hex_eq!(
            "40000000499602D2",
            XRPLPaymentAmount::Drops(1234567890)
            .xrpl_serialize()?
        );
        // maximum XRP
        assert_hex_eq!(
            "416345785D8A0000",
            XRPLPaymentAmount::Drops(100_000_000_000_000_000)
            .xrpl_serialize()?
        );
        // more than maximum XRP fails
        assert!(
            XRPLPaymentAmount::Drops(100_000_000_000_000_001)
            .xrpl_serialize()
            .is_err()
        );
        // account "0" (with length prefix)
        assert_hex_eq!(
            "140000000000000000000000000000000000000000",
            XRPLAddress("rrrrrrrrrrrrrrrrrrrrrhoLvTp".to_string())
            .xrpl_serialize()?
        );
        // account "1" (with length prefix)
        assert_hex_eq!(
            "140000000000000000000000000000000000000001",
            XRPLAddress("rrrrrrrrrrrrrrrrrrrrBZbvji".to_string())
            .xrpl_serialize()?
        );
        // max acccount
        assert_hex_eq!(
            "14FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            XRPLAddress("rQLbzfJH5BT1FS9apRLKV3G8dWEA5njaQi".to_string())
            .xrpl_serialize()?
        );
        assert_hex_eq!(
            "13000081140000000000000000000000000000000000000000E1",
            XRPLSignerEntry{
                account: "rrrrrrrrrrrrrrrrrrrrrhoLvTp".to_string(),
                signer_weight: 0
            }.xrpl_serialize()?
        );
        // { "NetworkID": 0 }
        assert_hex_eq!(
            "2100000000",
            XRPLObject { fields: vec![(2, 1, 0u32.xrpl_serialize()?)]}
            .xrpl_serialize()?
        );
        // empty array
        assert_hex_eq!(
            "F1",
            XRPLArray::<XRPLSignerEntry>{ field_code: 10, items: vec![] }
            .xrpl_serialize()?
        );
        // array with 1 element
        assert_hex_eq!(
            "EA13000081140000000000000000000000000000000000000000E1F1",
            XRPLArray::<XRPLSignerEntry>{ field_code: 10, items: vec![
                XRPLSignerEntry{
                    account: "rrrrrrrrrrrrrrrrrrrrrhoLvTp".to_string(),
                    signer_weight: 0
                },
            ] }
            .xrpl_serialize()?
        );
        Ok(())
    }

    #[test]
    fn serialize_xrpl_unsigned_token_payment_transaction() {
        let unsigned_tx = XRPLPaymentTx {
            account: "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ".to_string(),
            fee: 12,
            sequence: Sequence::Plain(1),
            amount: XRPLPaymentAmount::Token(
                XRPLToken {
                    currency: "JPY".to_string(),
                    issuer: "rrrrrrrrrrrrrrrrrrrrBZbvji".to_string(),
                },
                XRPLTokenAmount("0.3369568318".to_string()),
            ),
            destination: nonempty::String::try_from("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh").unwrap(),
            multisig_session_id: None,
        };
        let encoded_unsigned_tx = XRPLUnsignedTx::Payment(unsigned_tx).xrpl_serialize().unwrap();
        assert_eq!(
            "534D54001200002200000000240000000161D44BF89AC2A40B800000000000000000000000004A50590000000000000000000000000000000000000000000000000168400000000000000C730081145B812C9D57731E27A2DA8B1830195F88EF32A3B68314B5F762798A53D543A014CAF8B297CFF8F2F937E8",
            hex::encode_upper(encoded_unsigned_tx)
        );
    }

    #[test]
    fn serialize_xrpl_unsigned_xrp_payment_transaction() {
        let tx = XRPLPaymentTx {
            account: "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ".to_string(),
            fee: 10,
            sequence: Sequence::Plain(1),
            amount: XRPLPaymentAmount::Drops(1000),
            destination: nonempty::String::try_from("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh").unwrap(),
            multisig_session_id: None,
        };
        let encoded_unsigned_tx = &XRPLUnsignedTx::Payment(tx).xrpl_serialize().unwrap();
        assert_eq!(
            "534D5400120000220000000024000000016140000000000003E868400000000000000A730081145B812C9D57731E27A2DA8B1830195F88EF32A3B68314B5F762798A53D543A014CAF8B297CFF8F2F937E8",
            hex::encode_upper(encoded_unsigned_tx)
        );

        let tx = XRPLPaymentTx {
            account: "rhKnz85JUKcrAizwxNUDfqCvaUi9ZMhuwj".to_string(),
            fee: 3,
            sequence: Sequence::Plain(43497363),
            amount: XRPLPaymentAmount::Drops(1000000000),
            destination: nonempty::String::try_from("rw2521mDNXyKzHBrFGZ5Rj4wzUjS9FbiZq").unwrap(),
            multisig_session_id: None,
        };
        let encoded_unsigned_tx = &XRPLUnsignedTx::Payment(tx).xrpl_serialize().unwrap();
        assert_eq!(
            "534D54001200002200000000240297B79361400000003B9ACA0068400000000000000373008114245409103F1B06F22FBCED389AAE0EFCE2F6689A83146919924835FA51D3991CDF5CF4505781227686E6",
            hex::encode_upper(encoded_unsigned_tx)
        );
    }

    #[test]
    fn serialize_xrpl_signed_xrp_payment_transaction() {
        let signed_tx = XRPLSignedTransaction {
            unsigned_tx: XRPLUnsignedTx::Payment(XRPLPaymentTx {
                account: "rfEf91bLxrTVC76vw1W3Ur8Jk4Lwujskmb".to_string(),
                fee: 30,
                sequence: Sequence::Ticket(44218193),
                amount: XRPLPaymentAmount::Drops(100000000),
                destination: nonempty::String::try_from("rfgqgX62inhKsfti1NR6FeMS8NcQJCFniG").unwrap(),
                multisig_session_id: Some(Uint64::from(5461264u64)),
            }), signers: vec![
                XRPLSigner{
                    account: "r3mJFUQeVQma7qucT4iQSNCWuijVCPcicZ".to_string(),
                    txn_signature: HexBinary::from(hex::decode("3044022023DD4545108D411008FC9A76A58E1573AB0F8786413C8F38A92B1E2EAED60014022012A0A7890BFD0F0C8EA2C342107F65D4C91CAC29AAF3CF2840350BF3FB91E045").unwrap()),
                    signing_pub_key: PublicKey::try_from((KeyType::Ecdsa, HexBinary::from(hex::decode("025E0231BFAD810E5276E2CF9EB2F3F380CE0BDF6D84C3B6173499D3DDCC008856").unwrap()))).unwrap(),
                },
                XRPLSigner{
                    account: "rHxbKjRSFUUyuiio1jnFhimJRVAYYaGj7f".to_string(),
                    txn_signature: HexBinary::from(hex::decode("3045022100FC1490C236AD05A306EB5FD89072F14FEFC19ED35EB61BACD294D10E0910EDB102205A4CF0C0A759D7158A8FEE2F526C70277910DE88BF85564A1B3142AE635C9CE9").unwrap()),
                    signing_pub_key: PublicKey::try_from((KeyType::Ecdsa, HexBinary::from(hex::decode("036FF6F4B2BC5E08ABA924BD8FD986608F3685CA651A015B3D9D6A656DE14769FE").unwrap()))).unwrap(),
                }
            ],
        };
        let encoded_signed_tx = &signed_tx.xrpl_serialize().unwrap();
        assert_eq!(
            "12000022000000002400000000202902A2B751614000000005F5E10068400000000000001E73008114447BB6E37CA4D5D89FC2E2470A64632DA9BDD9E4831449599D50E0C1AC0CFC8D3B2A30830F3738EACC3EF3E0107321025E0231BFAD810E5276E2CF9EB2F3F380CE0BDF6D84C3B6173499D3DDCC00885674463044022023DD4545108D411008FC9A76A58E1573AB0F8786413C8F38A92B1E2EAED60014022012A0A7890BFD0F0C8EA2C342107F65D4C91CAC29AAF3CF2840350BF3FB91E0458114552A0D8EFCF978186CA9C37112B502D3728DA9EFE1E0107321036FF6F4B2BC5E08ABA924BD8FD986608F3685CA651A015B3D9D6A656DE14769FE74473045022100FC1490C236AD05A306EB5FD89072F14FEFC19ED35EB61BACD294D10E0910EDB102205A4CF0C0A759D7158A8FEE2F526C70277910DE88BF85564A1B3142AE635C9CE98114BA058AB3573EA34DC934D60E719A12DE6C213DE2E1F1F9EA7D03535510E1F1",
            hex::encode_upper(encoded_signed_tx)
        );
    }

    #[test]
    fn tx_serialization_sort_signers() {
        let signed_tx = XRPLSignedTransaction {
            unsigned_tx: XRPLUnsignedTx::Payment(XRPLPaymentTx {
                account: "rfEf91bLxrTVC76vw1W3Ur8Jk4Lwujskmb".to_string(),
                fee: 30,
                sequence: Sequence::Ticket(44218193),
                amount: XRPLPaymentAmount::Drops(100000000),
                destination: nonempty::String::try_from("rfgqgX62inhKsfti1NR6FeMS8NcQJCFniG").unwrap(),
                multisig_session_id: Some(Uint64::from(5461264u64)),
            }), signers: vec![
                XRPLSigner{
                    account: "rHxbKjRSFUUyuiio1jnFhimJRVAYYaGj7f".to_string(),
                    txn_signature: HexBinary::from(hex::decode("3045022100FC1490C236AD05A306EB5FD89072F14FEFC19ED35EB61BACD294D10E0910EDB102205A4CF0C0A759D7158A8FEE2F526C70277910DE88BF85564A1B3142AE635C9CE9").unwrap()),
                    signing_pub_key: PublicKey::try_from((KeyType::Ecdsa, HexBinary::from(hex::decode("036FF6F4B2BC5E08ABA924BD8FD986608F3685CA651A015B3D9D6A656DE14769FE").unwrap()))).unwrap(),
                },
                XRPLSigner{
                    account: "r3mJFUQeVQma7qucT4iQSNCWuijVCPcicZ".to_string(),
                    txn_signature: HexBinary::from(hex::decode("3044022023DD4545108D411008FC9A76A58E1573AB0F8786413C8F38A92B1E2EAED60014022012A0A7890BFD0F0C8EA2C342107F65D4C91CAC29AAF3CF2840350BF3FB91E045").unwrap()),
                    signing_pub_key: PublicKey::try_from((KeyType::Ecdsa, HexBinary::from(hex::decode("025E0231BFAD810E5276E2CF9EB2F3F380CE0BDF6D84C3B6173499D3DDCC008856").unwrap()))).unwrap(),
                },
            ],
        };
        let encoded_signed_tx = &signed_tx.xrpl_serialize().unwrap();
        assert_eq!(
            "12000022000000002400000000202902A2B751614000000005F5E10068400000000000001E73008114447BB6E37CA4D5D89FC2E2470A64632DA9BDD9E4831449599D50E0C1AC0CFC8D3B2A30830F3738EACC3EF3E0107321025E0231BFAD810E5276E2CF9EB2F3F380CE0BDF6D84C3B6173499D3DDCC00885674463044022023DD4545108D411008FC9A76A58E1573AB0F8786413C8F38A92B1E2EAED60014022012A0A7890BFD0F0C8EA2C342107F65D4C91CAC29AAF3CF2840350BF3FB91E0458114552A0D8EFCF978186CA9C37112B502D3728DA9EFE1E0107321036FF6F4B2BC5E08ABA924BD8FD986608F3685CA651A015B3D9D6A656DE14769FE74473045022100FC1490C236AD05A306EB5FD89072F14FEFC19ED35EB61BACD294D10E0910EDB102205A4CF0C0A759D7158A8FEE2F526C70277910DE88BF85564A1B3142AE635C9CE98114BA058AB3573EA34DC934D60E719A12DE6C213DE2E1F1F9EA7D03535510E1F1",
            hex::encode_upper(encoded_signed_tx)
        );
    }

    #[test]
    fn tx_serialization_ed25519_signers() {
        let signed_tx = XRPLSignedTransaction {
            unsigned_tx: XRPLUnsignedTx::Payment(XRPLPaymentTx {
                account: "r4ZMbbb4Y3KoeexmjEeTdhqUBrYjjWdyGM".to_string(),
                fee: 30,
                sequence: Sequence::Ticket(45205896),
                amount: XRPLPaymentAmount::Token(XRPLToken{ currency: "ETH".to_string(), issuer: "r4ZMbbb4Y3KoeexmjEeTdhqUBrYjjWdyGM".to_string() }, XRPLTokenAmount("100000000".to_string())),
                destination: nonempty::String::try_from("raNVNWvhUQzFkDDTdEw3roXRJfMJFVJuQo").unwrap(),
                multisig_session_id: Some(Uint64::from(5461264u64)),
            }), signers: vec![
                XRPLSigner{
                    account: "rBTmbPMAWghUv52pCCtkLYh5SPVy2PuDSj".to_string(),
                    txn_signature: HexBinary::from(hex::decode("531B9E854C81AEFA573C00DF1603C3DE80C1F3680D39A80F3FB725A0388D177E3EC5E28AD6760D9EEF8203FEB1FC61F9D9451F777114B97943E5702B54589E09").unwrap()),
                    signing_pub_key: PublicKey::try_from((KeyType::Ed25519, HexBinary::from(hex::decode("45e67eaf446e6c26eb3a2b55b64339ecf3a4d1d03180bee20eb5afdd23fa644f").unwrap()))).unwrap(),
                },
                XRPLSigner{
                    account: "rhAdaMDgF89314TfNRHc5GsA6LQZdk35S5".to_string(),
                    txn_signature: HexBinary::from(hex::decode("76CF2097D7038B90445CB952AE52CBDBE6D55FE7C0562493FE3D9AAE5E05A66A43777CBCDAA89233CAFD4D1D0F9B02DB0619B9BB14957CC3ADAA8D7D343E0106").unwrap()),
                    signing_pub_key: PublicKey::try_from((KeyType::Ed25519, HexBinary::from(hex::decode("dd9822c7fa239dda9913ebee813ecbe69e35d88ff651548d5cc42c033a8a667b").unwrap()))).unwrap(),
                },
            ],
        };
        let encoded_signed_tx = &signed_tx.xrpl_serialize().unwrap();
        assert_eq!(
            "12000022000000002400000000202902B1C98861D6838D7EA4C680000000000000000000000000004554480000000000EC792533BC26024CFAA5DDC2D04128E59581309C68400000000000001E73008114EC792533BC26024CFAA5DDC2D04128E59581309C831439659AAAD4DC8603798352FCF954419A67977536F3E0107321EDDD9822C7FA239DDA9913EBEE813ECBE69E35D88FF651548D5CC42C033A8A667B744076CF2097D7038B90445CB952AE52CBDBE6D55FE7C0562493FE3D9AAE5E05A66A43777CBCDAA89233CAFD4D1D0F9B02DB0619B9BB14957CC3ADAA8D7D343E010681142B3CF7B1986F5CB4EFEF11F933F40EC3106412C2E1E0107321ED45E67EAF446E6C26EB3A2B55B64339ECF3A4D1D03180BEE20EB5AFDD23FA644F7440531B9E854C81AEFA573C00DF1603C3DE80C1F3680D39A80F3FB725A0388D177E3EC5E28AD6760D9EEF8203FEB1FC61F9D9451F777114B97943E5702B54589E09811472C14C0DB6CEF64A87CC3D152D7B0E917D372BE7E1F1F9EA7D03535510E1F1",
            hex::encode_upper(encoded_signed_tx)
        );
    }


    #[test]
    fn serialize_xrpl_signed_xrp_ticket_create_transaction() {
        let signed_tx = XRPLSignedTransaction {
            unsigned_tx: XRPLUnsignedTx::TicketCreate(XRPLTicketCreateTx {
                account: "rfEf91bLxrTVC76vw1W3Ur8Jk4Lwujskmb".to_string(),
                fee: 30,
                sequence: Sequence::Plain(44218194),
                ticket_count: 3,
                multisig_session_id: Some(Uint64::from(5461264u64)),
            }), signers: vec![
                XRPLSigner{
                    account: "r3mJFUQeVQma7qucT4iQSNCWuijVCPcicZ".to_string(),
                    txn_signature: HexBinary::from(hex::decode("304402203C10D5295AE4A34FD702355B075E951CF9FFE3A73F8B7557FB68E5DF64D87D3702200945D65BAAD7F10A14EA57E08914005F412709D10F27D868D63BE3052F30363F").unwrap()),
                    signing_pub_key: PublicKey::try_from((KeyType::Ecdsa, HexBinary::from(hex::decode("025E0231BFAD810E5276E2CF9EB2F3F380CE0BDF6D84C3B6173499D3DDCC008856").unwrap()))).unwrap(),
                },
                XRPLSigner{
                    account: "rHxbKjRSFUUyuiio1jnFhimJRVAYYaGj7f".to_string(),
                    txn_signature: HexBinary::from(hex::decode("3045022100EF2CBAC3B2D81E1E3502B064BA198D9D0D3F1FFE6604DAC5019C53C262B5F9E7022000808A438BD5CA808649DCDA6766D2BA0E8FA7E94150675F73FC41B2F73C9C58").unwrap()),
                    signing_pub_key: PublicKey::try_from((KeyType::Ecdsa, HexBinary::from(hex::decode("036FF6F4B2BC5E08ABA924BD8FD986608F3685CA651A015B3D9D6A656DE14769FE").unwrap()))).unwrap(),
                },
            ]
        };
        let encoded_signed_tx = signed_tx.xrpl_serialize().unwrap();
        assert_eq!(
            "12000A22000000002402A2B75220280000000368400000000000001E73008114447BB6E37CA4D5D89FC2E2470A64632DA9BDD9E4F3E0107321025E0231BFAD810E5276E2CF9EB2F3F380CE0BDF6D84C3B6173499D3DDCC0088567446304402203C10D5295AE4A34FD702355B075E951CF9FFE3A73F8B7557FB68E5DF64D87D3702200945D65BAAD7F10A14EA57E08914005F412709D10F27D868D63BE3052F30363F8114552A0D8EFCF978186CA9C37112B502D3728DA9EFE1E0107321036FF6F4B2BC5E08ABA924BD8FD986608F3685CA651A015B3D9D6A656DE14769FE74473045022100EF2CBAC3B2D81E1E3502B064BA198D9D0D3F1FFE6604DAC5019C53C262B5F9E7022000808A438BD5CA808649DCDA6766D2BA0E8FA7E94150675F73FC41B2F73C9C588114BA058AB3573EA34DC934D60E719A12DE6C213DE2E1F1F9EA7D03535510E1F1",
            hex::encode_upper(encoded_signed_tx)
        );
    }

    #[test]
    fn serialize_xrpl_signed_signer_list_set_transaction() {
        let signed_tx = XRPLSignedTransaction {
            unsigned_tx: XRPLUnsignedTx::SignerListSet(XRPLSignerListSetTx {
                account: "rfEf91bLxrTVC76vw1W3Ur8Jk4Lwujskmb".to_string(),
                fee: 30,
                sequence: Sequence::Plain(44218445),
                signer_quorum: 3,
                signer_entries: vec![
                    XRPLSignerEntry{
                        account: "r3mJFUQeVQma7qucT4iQSNCWuijVCPcicZ".to_string(),
                        signer_weight: 2
                    },
                    XRPLSignerEntry{
                        account: "rHxbKjRSFUUyuiio1jnFhimJRVAYYaGj7f".to_string(),
                        signer_weight: 1
                    }
                ],
                multisig_session_id: Some(Uint64::from(5461264u64))
            }), signers: vec![
                XRPLSigner{
                    account: "r3mJFUQeVQma7qucT4iQSNCWuijVCPcicZ".to_string(),
                    txn_signature: HexBinary::from(hex::decode("3045022100B94B346A418BE9EF5AEE7806EE984E3E9B48EB4ED48E79B5BFB69C607167023E02206B14BD72B69206D14DADA82ACCDD2539D275719FB187ECE2A46BAC9025877B39").unwrap()),
                    signing_pub_key: PublicKey::try_from((KeyType::Ecdsa, HexBinary::from(hex::decode("025E0231BFAD810E5276E2CF9EB2F3F380CE0BDF6D84C3B6173499D3DDCC008856").unwrap()))).unwrap(),
                },
                XRPLSigner{
                    account: "rHxbKjRSFUUyuiio1jnFhimJRVAYYaGj7f".to_string(),
                    txn_signature: HexBinary::from(hex::decode("3044022072A1028FF972D9D6E950810AF72443EEE352ADB1BC54B1112983842C857C464502206D74A77387979A47863F08F9191611D142C2BD6B32D5C750EF58513C5669F21A").unwrap()),
                    signing_pub_key: PublicKey::try_from((KeyType::Ecdsa, HexBinary::from(hex::decode("036FF6F4B2BC5E08ABA924BD8FD986608F3685CA651A015B3D9D6A656DE14769FE").unwrap()))).unwrap(),
                },
            ],
        };
        let encoded_signed_tx = signed_tx.xrpl_serialize().unwrap();
        assert_eq!(
            "12000C22000000002402A2B84D20230000000368400000000000001E73008114447BB6E37CA4D5D89FC2E2470A64632DA9BDD9E4F3E0107321025E0231BFAD810E5276E2CF9EB2F3F380CE0BDF6D84C3B6173499D3DDCC00885674473045022100B94B346A418BE9EF5AEE7806EE984E3E9B48EB4ED48E79B5BFB69C607167023E02206B14BD72B69206D14DADA82ACCDD2539D275719FB187ECE2A46BAC9025877B398114552A0D8EFCF978186CA9C37112B502D3728DA9EFE1E0107321036FF6F4B2BC5E08ABA924BD8FD986608F3685CA651A015B3D9D6A656DE14769FE74463044022072A1028FF972D9D6E950810AF72443EEE352ADB1BC54B1112983842C857C464502206D74A77387979A47863F08F9191611D142C2BD6B32D5C750EF58513C5669F21A8114BA058AB3573EA34DC934D60E719A12DE6C213DE2E1F1F4EB1300028114552A0D8EFCF978186CA9C37112B502D3728DA9EFE1EB1300018114BA058AB3573EA34DC934D60E719A12DE6C213DE2E1F1F9EA7D03535510E1F1",
            hex::encode_upper(encoded_signed_tx)
        );
    }

    #[test]
    fn ed25519_public_key_to_xrpl_address() {
        assert_eq!(
            public_key_to_xrpl_address(PublicKey::Ed25519(HexBinary::from(hex::decode("ED9434799226374926EDA3B54B1B461B4ABF7237962EAE18528FEA67595397FA32").unwrap()))),
            "rDTXLQ7ZKZVKz33zJbHjgVShjsBnqMBhmN"
        );
    }

    #[test]
    fn secp256k1_public_key_to_xrpl_address() {
        assert_eq!(
            public_key_to_xrpl_address(PublicKey::Ecdsa(HexBinary::from(hex::decode("0303E20EC6B4A39A629815AE02C0A1393B9225E3B890CAE45B59F42FA29BE9668D").unwrap()))),
            "rnBFvgZphmN39GWzUJeUitaP22Fr9be75H"
        );
    }
}
