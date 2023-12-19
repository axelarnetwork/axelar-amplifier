use std::collections::BTreeSet;

use axelar_wasm_std::nonempty;
use connection_router::state::CrossChainId;
use cosmwasm_schema::{cw_serde, serde::Serializer};
use cosmwasm_std::{Storage, HexBinary};
use ripemd::Ripemd160;
use sha2::{Sha512, Digest, Sha256};

use crate::{
    error::ContractError,
    state::{Config, LAST_ASSIGNED_TICKET_NUMBER, AVAILABLE_TICKETS, TRANSACTION_INFO, NEXT_SEQUENCE_NUMBER, CONFIRMED_TRANSACTIONS, MESSAGE_ID_TO_TICKET, LATEST_SEQUENTIAL_TX_HASH, SIGNED_TO_UNSIGNED_TX_HASH},
    types::*, axelar_workers::{WorkerSet, AxelarSigner},
};

fn itoa_serialize<S>(x: &u64, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&x.to_string()[..])
}

#[cw_serde]
pub struct XRPLTokenAmount(pub String);

#[cw_serde]
#[serde(untagged)]
pub enum XRPLPaymentAmount {
    Drops(
        #[serde(serialize_with = "itoa_serialize")]
        u64,
    ),
    Token(XRPLToken, XRPLTokenAmount),
}

#[cw_serde]
#[serde(untagged)]
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
#[serde(rename_all = "PascalCase")]
pub struct XRPLTxCommonFields {
    pub account: String, // TODO: redundant here?
    #[serde(serialize_with = "itoa_serialize")]
    pub fee: u64,
    pub sequence: Sequence,
    pub signing_pub_key: String,
}

#[cw_serde]
#[serde(rename_all = "PascalCase", tag = "SignerEntry")]
pub struct XRPLSignerEntry {
    pub account: String,
    pub signer_weight: u16,
}

#[cw_serde]
#[serde(rename_all = "PascalCase")]
pub struct XRPLUnsignedTx {
    #[serde(flatten)]
    pub common: XRPLTxCommonFields,
    #[serde(flatten)]
    pub partial: XRPLPartialTx,
}

#[cw_serde]
#[serde(tag="TransactionType")]
pub enum XRPLPartialTx {
    Payment {
        amount: XRPLPaymentAmount,
        destination: nonempty::String,
    },
    SignerListSet {
        signer_quorum: u32,
        signer_entries: Vec<XRPLSignerEntry>,
    },
    TicketCreate {
        ticket_count: u32,
    },
}

impl XRPLUnsignedTx {
    pub fn sequence_number_increment(&self, status: TransactionStatus) -> u32 {
        if status == TransactionStatus::Pending || status == TransactionStatus::FailedOffChain {
            return 0;
        }

        match self.partial {
            XRPLPartialTx::Payment { .. } |
            XRPLPartialTx::SignerListSet { .. } => {
                match self.common.sequence {
                    Sequence::Plain(_) => 1,
                    Sequence::Ticket(_) => 0,
                }
            },
            XRPLPartialTx::TicketCreate { ticket_count } => {
                match status {
                    TransactionStatus::Succeeded => ticket_count + 1,
                    TransactionStatus::FailedOnChain => 1,
                    TransactionStatus::FailedOffChain |
                    TransactionStatus::Pending => unreachable!(),
                }
            },
        }
    }
}

#[cw_serde]
#[serde(rename_all = "PascalCase")]
pub struct XRPLSigner {
    pub account: String,
    pub txn_signature: HexBinary,
    pub signing_pub_key: HexBinary,
}

#[cw_serde]
#[serde(rename_all = "PascalCase")]
pub struct XRPLSignedTransaction {
    #[serde(flatten)]
    pub unsigned_tx: XRPLUnsignedTx,
    pub signers: Vec<XRPLSigner>,
}

pub fn get_next_ticket_number(storage: &dyn Storage) -> Result<u32, ContractError> {
    let last_assigned_ticket_number = LAST_ASSIGNED_TICKET_NUMBER.load(storage)?;
    let available_tickets = AVAILABLE_TICKETS.load(storage)?;

    // find next largest in available, otherwise use available_tickets[0]
    let ticket_number = available_tickets.iter().find(|&x| x > &last_assigned_ticket_number).unwrap_or(&available_tickets[0]);
    Ok(*ticket_number)
}

pub fn available_ticket_count(storage: &mut dyn Storage) -> Result<u32, ContractError> {
    let available_tickets = AVAILABLE_TICKETS.load(storage)?;
    let ticket_count = 250 - (available_tickets.len() as u32);
    Ok(ticket_count)
}

fn construct_unsigned_tx(
    config: &Config,
    partial_unsigned_tx: XRPLPartialTx,
    sequence: Sequence,
) -> XRPLUnsignedTx {
    let unsigned_tx_common = XRPLTxCommonFields {
        account: config.xrpl_multisig_address.to_string(),
        fee: config.xrpl_fee,
        sequence: sequence.clone(),
        signing_pub_key: "".to_string(),
    };

    XRPLUnsignedTx {
        common: unsigned_tx_common,
        partial: partial_unsigned_tx,
    }
}

const PAYMENT_TYPE: u16 = 0;
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

pub fn serialize_uint16(field_code: u8, value: u16) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend(field_id(UINT16_TYPE_CODE, field_code));
    result.extend(&value.to_be_bytes());
    result
}

pub fn serialize_uint32(field_code: u8, value: u32) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend(field_id(UINT32_TYPE_CODE, field_code));
    result.extend(&value.to_be_bytes());
    result
}

const POSITIVE_BIT: u64 = 0x4000000000000000;

const MIN_MANTISSA: u128 = 1_000_000_000_000_000;
const MAX_MANTISSA: u128 = 10_000_000_000_000_000 - 1;
const MIN_EXPONENT: i32 = -96;
const MAX_EXPONENT: i32 = 80;

// TODO: trim whitespace?
fn parse_decimal(s: &str) -> Result<(bool, u64, u64), ContractError> {
    if s.is_empty() {
        return Err(ContractError::InvalidAmount);
    }

    let sign = s.starts_with('-');
    let trimmed = if s.starts_with('-') || s.starts_with('+') { &s[1..] } else { s };

    let parts: Vec<_> = trimmed.split('.').collect();

    if parts.len() > 2 {
        return Err(ContractError::InvalidAmount);
    }

    let integer_part = match parts[0].parse::<u64>() {
        Ok(num) => num,
        Err(_) => return Err(ContractError::InvalidAmount),
    };

    let fractional_part = if parts.len() == 2 {
        match parts[1].parse::<u64>() {
            Ok(num) => num,
            Err(_) => return Err(ContractError::InvalidAmount),
        }
    } else {
        0
    };

    Ok((sign, integer_part, fractional_part))
}

// see https://github.com/XRPLF/xrpl-dev-portal/blob/82da0e53a8d6cdf2b94a80594541d868b4d03b94/content/_code-samples/tx-serialization/py/xrpl_num.py#L19
pub fn amount_to_bytes(amount: XRPLTokenAmount) -> Result<Vec<u8>, ContractError> {
    let (is_negative, integer_part, fractional_part) = parse_decimal(amount.0.trim())?;

    let mut serial: u64 = 0x8000000000000000;
    if integer_part == 0 && fractional_part == 0 {
        return Ok(Vec::from(serial.to_be_bytes()))
    }

    let mut exponent: i32 = fractional_part.to_string().len() as i32;
    let mut mantissa: u128 = (integer_part as u128) * 10u128.pow(exponent as u32) + (fractional_part as u128);

    while mantissa < MIN_MANTISSA && exponent > MIN_EXPONENT {
        mantissa *= 10;
        exponent -= 1;
    }

    /*
    TODO: Discuss with Ripple team, the below is part of the reference implementation
    https://github.com/XRPLF/rippled/blob/master/src/ripple/protocol/impl/STAmount.cpp#L795
    However it leads to least significant digits being dropped off from the mantissa */
    while mantissa > MAX_MANTISSA && exponent > MIN_EXPONENT {
        if exponent > MAX_EXPONENT {
            return Err(ContractError::InvalidAmount);
        }
        mantissa /= 10;
        exponent += 1;
    }

    if exponent < MIN_EXPONENT || mantissa < MIN_MANTISSA {
        return Ok(Vec::from(serial.to_be_bytes()));
    }

    if exponent > MAX_EXPONENT || mantissa > MAX_MANTISSA {
        return Err(ContractError::InvalidAmount);
    }

    if !is_negative {
        serial |= 0x4000000000000000; // set positive bit
    }

    serial |= ((exponent+97) as u64) << 54; // next 8 bits are exponent

    serial |= mantissa as u64; // last 54 bits are mantissa

    Ok(Vec::from(serial.to_be_bytes()))
}


pub fn currency_to_bytes(currency: String) -> Result<[u8; 20], ContractError> {
    if currency.len() != 3 || !currency.is_ascii() {
        return Err(ContractError::InvalidCurrency);
    }
    let mut buffer = [0u8; 20];
    buffer[12..15].copy_from_slice(currency.as_bytes());
    Ok(buffer)
}

pub fn decode_address(address: String) -> Result<[u8; 20], ContractError> {
    let res = bs58::decode(address).with_alphabet(bs58::Alphabet::RIPPLE).into_vec().unwrap();
    // .map_err(|_| ContractError::InvalidAddress)?;
    println!("decoded {:?} {}", res, res.len());
    if res.len() != 25 {
        return Err(ContractError::InvalidAddress);
    }
    let mut buffer = [0u8; 20];
    buffer.copy_from_slice(&res[1..21]);
    return Ok(buffer)
}

pub fn serialize_amount(field_code: u8, amount: XRPLPaymentAmount) -> Result<Vec<u8>, ContractError> {
    let mut result = Vec::new();
    println!("amount field id {} {} {}", AMOUNT_TYPE_CODE, field_code, hex::encode(field_id(AMOUNT_TYPE_CODE, field_code)));
    result.extend(field_id(AMOUNT_TYPE_CODE, field_code));
    match amount {
        XRPLPaymentAmount::Drops(value) => {
            // assert!(value >= 0);
            assert!(value <= 10u64.pow(17));
            result.extend((value | POSITIVE_BIT).to_be_bytes());
        },
        XRPLPaymentAmount::Token(token, amount) => {
            result.extend(amount_to_bytes(amount)?);
            result.extend(currency_to_bytes(token.currency)?);
            result.extend(decode_address(token.issuer)?);
        }
    }
    Ok(result)
}

// see https://github.com/XRPLF/xrpl-dev-portal/blob/master/content/_code-samples/tx-serialization/py/serialize.py#L92
// returns None if length too big
pub fn encode_length(mut length: usize) -> Option<Vec<u8>> {
    if length <= 192 {
        return Some(vec![length as u8]);
    } else if length <= 12480 {
        length -= 193;
        return Some(vec![(length >> 8) as u8, (length & 0xff) as u8]);
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

pub fn serialize_blob(field_code: u8, blob: Vec<u8>) -> Option<Vec<u8>> {
    let mut result: Vec<u8> = Vec::new();
    result.extend(field_id(BLOB_TYPE_CODE, field_code));
    result.extend(encode_length(blob.len())?);
    result.extend(blob);
    Some(result)
}

pub fn serialize_signer(signer: &XRPLSigner) -> Result<Vec<u8>, ContractError> {
    let mut results: Vec<Vec<u8>> = Vec::new();
    results.push(field_id(OBJECT_TYPE_CODE, 16));
    results.push(serialize_blob(3, signer.signing_pub_key.clone().as_slice().to_vec()).ok_or(ContractError::InvalidSigningPubKey)?);
    results.push(serialize_blob(4, signer.txn_signature.clone().as_slice().to_vec()).ok_or(ContractError::InvalidSignature)?);
    results.push(serialize_account_id(1, signer.account.clone())?);
    results.push(field_id(OBJECT_TYPE_CODE, 1));
    println!("signer hex parts {}", results.iter().map(|x| hex::encode(x)).collect::<Vec<String>>().join(","));
    Ok(results.concat())
}

pub fn serialize_signers_array(field_code: u8, signers: Vec<XRPLSigner>) -> Result<Vec<u8>, ContractError> {
    let mut result: Vec<u8> = Vec::new();
    result.extend(field_id(ARRAY_TYPE_CODE, field_code));
    for signer in &signers {
        result.extend(serialize_signer(signer)?);
    }
    result.extend(field_id(ARRAY_TYPE_CODE, 1));
    Ok(result)
}

pub fn serialize_account_id(field_code: u8, account_id: String) -> Result<Vec<u8>, ContractError> {
    let mut result: Vec<u8> = Vec::new();
    result.extend(field_id(ACCOUNT_ID_TYPE_CODE, field_code));
    result.extend(vec![20]);
    result.extend(decode_address(account_id)?);
    Ok(result)
}

// TODO: each worker must append his decoded address to the serialized tx before signing
pub fn serialize_unsigned_payment_tx(common: XRPLTxCommonFields, amount: XRPLPaymentAmount, destination: nonempty::String) -> Result<Vec<u8>, ContractError> {
    let mut results: Vec<Vec<u8>> = Vec::new();
    // value: 0, type:uint16, type_code: 1,  nth: 2, !isVLEncoded
    // serialize_transaction_payment_type();
    results.push(Vec::from((0x534D5400 as u32).to_be_bytes())); // prefix for multisignature signing
    results.push(serialize_uint16(2, PAYMENT_TYPE));
    results.push(serialize_uint32(2, 0));
    match common.sequence {
        Sequence::Plain(seq) => {
            // type: Uint32, type_code: 2,  nth: 4, !isVLEncoded
            // serialize_sequence(seq);
            results.push(serialize_uint32(4, seq));
        },
        Sequence::Ticket(seq) => {
            // type: Uint32, type_code: 2, nth: 4, !isVLEncoded
            // serialize_sequence(seq)
            results.push(serialize_uint32(4, 0));
            // type: Uint32, type_code: 2, nth: 41, !isVLEncoded
            // serialize_ticket_sequence(seq);
            results.push(serialize_uint32(41, seq));
        }
    };
    // type: Amount, type_code: 6, nth: 1, !isVLEncoded
    results.push(serialize_amount(1, amount)?);
    // type: Amount, type_code: 6, nth: 8, !isVLEncoded
    results.push(serialize_amount(8, XRPLPaymentAmount::Drops(common.fee))?);
    // type: Blob, type_code: 7, nth: 3, isVLEncoded
    // TODO: hex::encode to slice?
    results.push(serialize_blob(3, hex::decode("").unwrap()).unwrap());
    // type: AccountId, type_code: 8, nth: 1, isVLEncoded
    results.push(serialize_account_id(1, common.account)?);
    // type: AccountId, type_code: 8, nth:3, isVLEncoded
    results.push(serialize_account_id(3, destination.into())?);

    println!("hex parts {}", results.iter().map(|x| hex::encode(x)).collect::<Vec<String>>().join(","));
    Ok(results.concat())
}

pub fn serialize_unsigned_tx(tx: XRPLUnsignedTx) -> Result<Vec<u8>, ContractError> {
    match tx.partial {
        XRPLPartialTx::Payment { amount, destination } => serialize_unsigned_payment_tx(tx.common, amount, destination),
        _ => unimplemented!()
    }
}

// TODO: each worker must append his decoded address to the serialized tx before signing
pub fn serialize_signed_payment_tx(signers: Vec<XRPLSigner>, common: XRPLTxCommonFields, amount: XRPLPaymentAmount, destination: nonempty::String) -> Result<Vec<u8>, ContractError> {
    let mut results: Vec<Vec<u8>> = Vec::new();
    // value: 0, type:uint16, type_code: 1,  nth: 2, !isVLEncoded
    // serialize_transaction_payment_type();
    results.push(serialize_uint16(2, PAYMENT_TYPE));
    results.push(serialize_uint32(2, 0));
    match common.sequence {
        Sequence::Plain(seq) => {
            // type: Uint32, type_code: 2,  nth: 4, !isVLEncoded
            // serialize_sequence(seq);
            results.push(serialize_uint32(4, seq));
        },
        Sequence::Ticket(seq) => {
            // type: Uint32, type_code: 2, nth: 4, !isVLEncoded
            // serialize_sequence(seq)
            results.push(serialize_uint32(4, 0));
            // type: Uint32, type_code: 2, nth: 41, !isVLEncoded
            // serialize_ticket_sequence(seq);
            results.push(serialize_uint32(41, seq));
        }
    };
    // type: Amount, type_code: 6, nth: 1, !isVLEncoded
    results.push(serialize_amount(1, amount)?);
    // type: Amount, type_code: 6, nth: 8, !isVLEncoded
    results.push(serialize_amount(8, XRPLPaymentAmount::Drops(common.fee))?);
    // type: Blob, type_code: 7, nth: 3, isVLEncoded
    // TODO: hex::encode to slice?
    results.push(serialize_blob(3, hex::decode("").unwrap()).unwrap());
    // type: AccountId, type_code: 8, nth: 1, isVLEncoded
    results.push(serialize_account_id(1, common.account)?);
    // type: AccountId, type_code: 8, nth:3, isVLEncoded
    results.push(serialize_account_id(3, destination.into())?);
    // type: STArray, type_code: 14, nth:3, !isVLEncoded
    results.push(serialize_signers_array(3, signers)?);

    println!("hex parts {}", results.iter().map(|x| hex::encode(x)).collect::<Vec<String>>().join(","));
    Ok(results.concat())
}

pub fn serialize_signed_tx(signed_tx: XRPLSignedTransaction) -> Result<Vec<u8>, ContractError> {
    match signed_tx.unsigned_tx.partial {
        XRPLPartialTx::Payment { amount, destination } => serialize_signed_payment_tx(signed_tx.signers, signed_tx.unsigned_tx.common, amount, destination),
        _ => unimplemented!()
    }
}

// TODO: optimize
pub fn compute_unsigned_tx_hash(unsigned_tx: XRPLUnsignedTx) -> Result<TxHash, ContractError> {
    let encoded_unsigned_tx = serialize_unsigned_tx(unsigned_tx)?;

    let tx_hash_hex: HexBinary = HexBinary::from(xrpl_hash(HASH_PREFIX_UNSIGNED_TRANSACTION_MULTI, encoded_unsigned_tx.as_slice()));
    let tx_hash: TxHash = TxHash(tx_hash_hex.clone());
    Ok(tx_hash)
}

pub fn compute_signed_tx_hash(encoded_signed_tx: Vec<u8>) -> Result<TxHash, ContractError> {
    let tx_hash_hex: HexBinary = HexBinary::from(xrpl_hash(HASH_PREFIX_SIGNED_TRANSACTION, encoded_signed_tx.as_slice()));
    let tx_hash: TxHash = TxHash(tx_hash_hex.clone());
    Ok(tx_hash)
}

pub const HASH_PREFIX_UNSIGNED_TRANSACTION_MULTI: [u8; 4] = [0x53, 0x4D, 0x54, 0x00];
pub const HASH_PREFIX_SIGNED_TRANSACTION: [u8; 4] = [0x54, 0x58, 0x4E, 0x00];

pub fn xrpl_hash(
    prefix: [u8; 4],
    tx_blob: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha512::new_with_prefix(prefix);
    hasher.update(tx_blob);
    let hash: [u8; 64] = hasher.finalize().into();
    let mut half_hash: [u8; 32] = [0; 32];
    half_hash.copy_from_slice(&hash[..32]);
    half_hash
}

fn issue_tx(
    storage: &mut dyn Storage,
    config: &Config,
    partial_unsigned_tx: XRPLPartialTx,
    sequence: Sequence,
    message_id: Option<CrossChainId>,
) -> Result<TxHash, ContractError> {
    let unsigned_tx = construct_unsigned_tx(
        config,
        partial_unsigned_tx,
        sequence.clone(),
    );

    let tx_hash = compute_unsigned_tx_hash(unsigned_tx.clone())?;

    TRANSACTION_INFO.save(
        storage,
        tx_hash.clone(),
        &TransactionInfo {
            status: TransactionStatus::Pending,
            unsigned_contents: unsigned_tx.clone(),
            message_id,
        }
    )?;

    match sequence {
        Sequence::Ticket(ticket_number) => {
            LAST_ASSIGNED_TICKET_NUMBER.save(storage, &ticket_number)?;
        },
        Sequence::Plain(_) => {
            LATEST_SEQUENTIAL_TX_HASH.save(storage, &tx_hash)?;
        },
    };

    Ok(tx_hash)
}

fn get_next_sequence_number(storage: &dyn Storage) -> Result<u32, ContractError> {
    let latest_sequential_tx_info = load_latest_sequential_tx_info(storage)?;
    let sequence_number = if latest_sequential_tx_info.status == TransactionStatus::Pending {
        latest_sequential_tx_info.unsigned_contents.common.sequence.clone().into()
    } else {
        NEXT_SEQUENCE_NUMBER.load(storage)?
    };
    Ok(sequence_number)
}

pub fn issue_ticket_create(storage: &mut dyn Storage, config: &Config, ticket_count: u32) -> Result<TxHash, ContractError> {
    let partial_unsigned_tx = XRPLPartialTx::TicketCreate {
        ticket_count,
    };

    let sequence_number = get_next_sequence_number(storage)?;

    let tx_hash = issue_tx(
        storage,
        config,
        partial_unsigned_tx,
        Sequence::Plain(sequence_number),
        None,
    )?;

    Ok(tx_hash)
}

fn load_latest_sequential_tx_info(
    storage: &dyn Storage,
) -> Result<TransactionInfo, ContractError> {
    let latest_sequential_tx_hash = LATEST_SEQUENTIAL_TX_HASH.load(storage)?;
    Ok(TRANSACTION_INFO.load(storage, latest_sequential_tx_hash.clone())?)
}

pub fn issue_payment(
    storage: &mut dyn Storage,
    config: &Config,
    destination: nonempty::String,
    amount: XRPLPaymentAmount,
    message_id: CrossChainId,
) -> Result<TxHash, ContractError> {
    let partial_unsigned_tx = XRPLPartialTx::Payment {
        destination,
        amount,
    };

    let ticket_number = assign_ticket_number(storage, message_id.clone())?;

    issue_tx(
        storage,
        config,
        partial_unsigned_tx,
        Sequence::Ticket(ticket_number),
        Some(message_id),
    )
}

pub fn public_key_to_xrpl_address(public_key: multisig::key::PublicKey) -> String {
    let public_key_hex: HexBinary = public_key.into();

    assert!(public_key_hex.len() == 33);

    let public_key_inner_hash = Sha256::digest(public_key_hex);
    let account_id = Ripemd160::digest(public_key_inner_hash);

    let address_type_prefix: &[u8] = &[0x00];
    let payload = [address_type_prefix, &account_id].concat();

    let checksum_hash1 = Sha256::digest(payload.clone());
    let checksum_hash2 = Sha256::digest(checksum_hash1);
    let checksum = &checksum_hash2[0..4];

    bs58::encode([payload, checksum.to_vec()].concat())
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_string()
}

pub fn make_xrpl_signer_entries(signers: BTreeSet<AxelarSigner>) -> Vec<XRPLSignerEntry> {
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

pub fn issue_signer_list_set(storage: &mut dyn Storage, config: &Config, workers: WorkerSet) -> Result<TxHash, ContractError> {
    let partial_unsigned_tx = XRPLPartialTx::SignerListSet {
        signer_quorum: workers.quorum,
        signer_entries: make_xrpl_signer_entries(workers.signers),
    };

    let sequence_number = get_next_sequence_number(storage)?;
    issue_tx(
        storage,
        config,
        partial_unsigned_tx,
        Sequence::Plain(sequence_number),
        None,
    )
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

pub fn update_tx_status(storage: &mut dyn Storage, tx_hash: TxHash, new_status: TransactionStatus) -> Result<(), ContractError> {
    let unsigned_tx_hash = SIGNED_TO_UNSIGNED_TX_HASH.load(storage, tx_hash.clone())?;
    let mut tx_info = TRANSACTION_INFO.load(storage, unsigned_tx_hash.clone())?;
    if tx_info.status != TransactionStatus::Pending {
        return Err(ContractError::TransactionStatusAlreadyUpdated);
    }

    tx_info.status = new_status.clone();

    let tx_sequence_number: u32 = tx_info.unsigned_contents.common.sequence.clone().into();
    if let XRPLPartialTx::TicketCreate { ticket_count } = tx_info.unsigned_contents.partial {
        if tx_info.status == TransactionStatus::Succeeded {
            mark_tickets_available(
                storage,
                (tx_sequence_number + 1)..(tx_sequence_number + ticket_count),
            )?;
        }
    }

    let sequence_number_increment = tx_info.unsigned_contents.sequence_number_increment(new_status.clone());
    if sequence_number_increment > 0 && tx_sequence_number == NEXT_SEQUENCE_NUMBER.load(storage)? {
        NEXT_SEQUENCE_NUMBER.save(storage, &(tx_sequence_number + sequence_number_increment))?;
    }

    if new_status == TransactionStatus::Succeeded || new_status == TransactionStatus::FailedOnChain {
        CONFIRMED_TRANSACTIONS.save(storage, tx_sequence_number, &unsigned_tx_hash)?;
        mark_ticket_unavailable(storage, tx_sequence_number)?;
    }

    TRANSACTION_INFO.save(storage, unsigned_tx_hash, &tx_info)?;
    Ok(())
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

        // or if it has been consumed by the same transactions.
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
    use multisig::key::PublicKey;

    use super::*;

    #[test]
    fn serialize_xrpl_unsigned_token_payment_transaction() {
        let unsigned_tx = XRPLUnsignedTx {
            common: XRPLTxCommonFields {
                account: "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ".to_string(),
                fee: 12,
                sequence: Sequence::Plain(1),
                signing_pub_key: "".to_string(),
            },
            partial: XRPLPartialTx::Payment {
                amount: XRPLPaymentAmount::Token(
                    XRPLToken {
                        currency: "JPY".to_string(),
                        issuer: "rrrrrrrrrrrrrrrrrrrrBZbvji".to_string(),
                    },
                    XRPLTokenAmount("0.3369568318".to_string()),
                ),
                destination: nonempty::String::try_from("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh").unwrap(),
            }
        };
        let encoded_unsigned_tx = serialize_unsigned_tx(unsigned_tx).unwrap();
        assert_eq!(
            "534D54001200002200000000240000000161D44BF89AC2A40B800000000000000000000000004A50590000000000000000000000000000000000000000000000000168400000000000000C730081145B812C9D57731E27A2DA8B1830195F88EF32A3B68314B5F762798A53D543A014CAF8B297CFF8F2F937E8",
            hex::encode_upper(encoded_unsigned_tx)
        );
    }

    #[test]
    fn serialize_xrpl_unsigned_xrp_payment_transaction() {
        let unsigned_tx = XRPLUnsignedTx {
            common: XRPLTxCommonFields {
                account: "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ".to_string(),
                fee: 10,
                sequence: Sequence::Plain(1),
                signing_pub_key: "".to_string(),
            },
            partial: XRPLPartialTx::Payment {
                amount: XRPLPaymentAmount::Drops(1000),
                destination: nonempty::String::try_from("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh").unwrap(),
            }
        };
        let encoded_unsigned_tx = serialize_unsigned_tx(unsigned_tx).unwrap();
        assert_eq!(
            "534D5400120000220000000024000000016140000000000003E868400000000000000A730081145B812C9D57731E27A2DA8B1830195F88EF32A3B68314B5F762798A53D543A014CAF8B297CFF8F2F937E8",
            hex::encode_upper(encoded_unsigned_tx)
        );

        let unsigned_tx = XRPLUnsignedTx {
            common: XRPLTxCommonFields {
                account: "rhKnz85JUKcrAizwxNUDfqCvaUi9ZMhuwj".to_string(),
                fee: 3,
                sequence: Sequence::Plain(43497363),
                signing_pub_key: "".to_string(),
            },
            partial: XRPLPartialTx::Payment {
                amount: XRPLPaymentAmount::Drops(1000000000),
                destination: nonempty::String::try_from("rw2521mDNXyKzHBrFGZ5Rj4wzUjS9FbiZq").unwrap(),
            }
        };
        let encoded_unsigned_tx = serialize_unsigned_tx(unsigned_tx).unwrap();
        assert_eq!(
            "534D54001200002200000000240297B79361400000003B9ACA0068400000000000000373008114245409103F1B06F22FBCED389AAE0EFCE2F6689A83146919924835FA51D3991CDF5CF4505781227686E6",
            hex::encode_upper(encoded_unsigned_tx)
        );
    }

    #[test]
    fn serialize_xrpl_signed_xrp_payment_transaction() {
        let signed_tx = XRPLSignedTransaction {
            unsigned_tx: XRPLUnsignedTx {
                common: XRPLTxCommonFields {
                    account: "rhKnz85JUKcrAizwxNUDfqCvaUi9ZMhuwj".to_string(),
                    fee: 30,
                    sequence: Sequence::Plain(43497365),
                    signing_pub_key: "".to_string(),
                },
                partial: XRPLPartialTx::Payment {
                    amount: XRPLPaymentAmount::Drops(1000000000),
                    destination: nonempty::String::try_from("rfgqgX62inhKsfti1NR6FeMS8NcQJCFniG").unwrap(),
                }
            }, signers: vec![
                XRPLSigner{
                    account: "rn7JWRhHvsvea6JMWYFuBB3MizMxbgKApf".to_string(),
                    txn_signature: HexBinary::from(hex::decode("00CBEDBDD84D5B17EC0D24EDEA49AE78D33908E69D2885895BC0243458228E8FD5CEF5ABCA558C3518D97B0BBA1C4051BBB31AAD6E7808673562FA73FFB5F50B").unwrap()),
                    signing_pub_key: HexBinary::from(hex::decode("EDDC432D6E86302084DCB8EBFA6EF7452DC8CBFA552D5F843D6BD1870EC9CD10F9").unwrap()),
                },
                XRPLSigner{
                    account: "rM9pYgHGm1Mqohp13XfZh6kbESkQPpJAKF".to_string(),
                    txn_signature: HexBinary::from(hex::decode("62B63EFF8ED37ACFA453A61EC98B13761EFE608E36EB437ABE42DC86B73C3114B2ED5E6C3E9428E82DC4AAB9E4A093C00F041F6F32A5392FDAEF858142F0CE02").unwrap()),
                    signing_pub_key: HexBinary::from(hex::decode("ED1B88E8E246E395E0CD45153E1579B1B43D7C1DF9B5481A34AABC43FF8562B435").unwrap()),
                }
            ]
        };
        let encoded_signed_tx = serialize_signed_tx(signed_tx).unwrap();
        assert_eq!(
            "1200002200000000240297B79561400000003B9ACA0068400000000000001E73008114245409103F1B06F22FBCED389AAE0EFCE2F6689A831449599D50E0C1AC0CFC8D3B2A30830F3738EACC3EF3E0107321EDDC432D6E86302084DCB8EBFA6EF7452DC8CBFA552D5F843D6BD1870EC9CD10F9744000CBEDBDD84D5B17EC0D24EDEA49AE78D33908E69D2885895BC0243458228E8FD5CEF5ABCA558C3518D97B0BBA1C4051BBB31AAD6E7808673562FA73FFB5F50B8114310A592CA22E8B35B819464F8A581A36C91DE857E1E0107321ED1B88E8E246E395E0CD45153E1579B1B43D7C1DF9B5481A34AABC43FF8562B435744062B63EFF8ED37ACFA453A61EC98B13761EFE608E36EB437ABE42DC86B73C3114B2ED5E6C3E9428E82DC4AAB9E4A093C00F041F6F32A5392FDAEF858142F0CE028114DCE722505E32B29932618C5C9819AAEA03754AA5E1F1",
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
