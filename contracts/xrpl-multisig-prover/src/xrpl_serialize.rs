use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint128};
use multisig::key::PublicKey;

use crate::{error::ContractError, xrpl_multisig::{Sequence, XRPLAccountId, XRPLPaymentAmount, XRPLPaymentTx, XRPLSignedTransaction, XRPLSigner, XRPLSignerEntry, XRPLSignerListSetTx, XRPLTicketCreateTx, XRPLUnsignedTx}};

const PAYMENT_TX_TYPE: u16 = 0;
const TICKET_CREATE_TX_TYPE: u16 = 10;
const SIGNER_LIST_SET_TX_TYPE: u16 = 12;

const POSITIVE_BIT: u64 = 0x4000000000000000;

pub trait XRPLSerialize {
    const TYPE_CODE: u8;
    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError>;
}

impl XRPLSerialize for u16 {
    const TYPE_CODE: u8 = 1;

    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError> {
        Ok(self.to_be_bytes().to_vec())
    }
}

impl XRPLSerialize for u32 {
    const TYPE_CODE: u8 = 2;
    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError> {
        Ok(self.to_be_bytes().to_vec())
    }
}

impl XRPLSerialize for XRPLPaymentAmount {
    const TYPE_CODE: u8 = 6;

    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError> {
        match self {
            XRPLPaymentAmount::Drops(value) => {
                if *value <= 10u64.pow(17) {
                    Ok((value | POSITIVE_BIT).to_be_bytes().to_vec())
                } else {
                    Err(ContractError::InvalidAmount { reason: "more than maximum amount of drops".to_string() })
                }
            },
            XRPLPaymentAmount::Token(token, amount) => {
                let mut result = Vec::new();
                result.extend(amount.to_bytes());
                result.extend(currency_to_bytes(&token.currency)?);
                result.extend(token.issuer.to_bytes());
                Ok(result)
            }
        }
    }
}

pub fn currency_to_bytes(currency: &String) -> Result<[u8; 20], ContractError> {
    if currency.len() != 3 || !currency.is_ascii() || currency == "XRP" {
        return Err(ContractError::InvalidCurrency);
    }
    let mut buffer = [0u8; 20];
    buffer[12..15].copy_from_slice(currency.as_bytes());
    Ok(buffer)
}

impl XRPLSerialize for HexBinary {
    const TYPE_CODE: u8 = 7;
    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError> {
        let encoded_length = encode_length(self.len())?;
        let mut result = Vec::new();
        result.extend(encoded_length);
        result.extend(self.to_vec());
        Ok(result)
    }
}

// see https://github.com/XRPLF/xrpl-dev-portal/blob/master/content/_code-samples/tx-serialization/py/serialize.py#L92
// may error if length too big
pub fn encode_length(mut length: usize) -> Result<Vec<u8>, ContractError> {
    if length <= 192 {
        Ok(vec![length as u8])
    } else if length <= 12480 {
        length -= 193;
        Ok(vec![193 + (length >> 8) as u8, (length & 0xff) as u8])
    } else if length <= 918744  {
        length -= 12481;
        Ok(vec![
            241 + (length >> 16) as u8,
            ((length >> 8) & 0xff) as u8,
            (length & 0xff) as u8
        ])
    } else {
        Err(ContractError::InvalidBlob)
    }
}

impl XRPLSerialize for PublicKey {
    const TYPE_CODE: u8 = 7;
    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError> {
        match self.clone() {
            // rippled prefixes Ed25519 public keys with the byte 0xED so both types of public key are 33 bytes.
            // https://xrpl.org/cryptographic-keys.html
            Self::Ed25519(hex) => HexBinary::from_hex(format!("ED{}", hex.to_hex()).as_str())?.xrpl_serialize(),
            Self::Ecdsa(hex) => hex.xrpl_serialize(),
        }
    }
}

#[derive(Clone)]
pub enum Field {
    SigningPubKey,
    TxnSignature,
    Account,
    SignerWeight,
    MemoData,
    TransactionType,
    Flags,
    Sequence,
    TicketSequence,
    Amount,
    Fee,
    Destination,
    SignerQuorum,
    SignerEntries,
    SignerEntry,
    Memos,
    Memo,
    TicketCount,
    Signers,
    Signer
}

impl Field {
    const fn to_u8(self) -> u8 {
        match self {
            Field::SigningPubKey => 3,
            Field::TxnSignature => 4,
            Field::Account => 1,
            Field::SignerWeight => 3,
            Field::MemoData => 13,
            Field::TransactionType => 2,
            Field::Flags => 2,
            Field::Amount => 1,
            Field::Fee => 8,
            Field::Destination => 3,
            Field::Sequence => 4,
            Field::TicketSequence => 41,
            Field::SignerQuorum => 35,
            Field::SignerEntries => 4,
            Field::SignerEntry => 11,
            Field::Memos => 9,
            Field::Memo => 10,
            Field::TicketCount => 40,
            Field::Signers => 3,
            Field::Signer => 16
        }
    }
}

impl TryInto<XRPLObject> for XRPLSigner {
    type Error = ContractError;

    fn try_into(self) -> Result<XRPLObject, ContractError> {
        let mut obj = XRPLObject::new();
        obj.add_field(Field::SigningPubKey, &self.signing_pub_key)?;
        obj.add_field(Field::TxnSignature, &self.txn_signature)?;
        obj.add_field(Field::Account, &self.account)?;
        Ok(obj)
    }
}

impl TryInto<XRPLObject> for XRPLSignerEntry {
    type Error = ContractError;

    fn try_into(self) -> Result<XRPLObject, ContractError> {
        let mut obj = XRPLObject::new();
        obj.add_field(Field::Account, &self.account)?;
        obj.add_field(Field::SignerWeight, &self.signer_weight)?;
        Ok(obj)
    }
}

#[derive(Clone)]
pub struct XRPLMemo(HexBinary);

impl Into<HexBinary> for XRPLMemo {
    fn into(self) -> HexBinary {
        return self.0;
    }
}

impl TryInto<XRPLObject> for XRPLMemo {
    type Error = ContractError;

    fn try_into(self) -> Result<XRPLObject, ContractError> {
        let mut obj = XRPLObject::new();
        let hex: HexBinary = self.into();
        obj.add_field(Field::MemoData, &hex)?;
        Ok(obj)
    }
}

impl XRPLSerialize for XRPLAccountId {
    const TYPE_CODE: u8 = 8;

    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError> {
        let mut result: Vec<u8> = Vec::new();
        result.extend(vec![self.to_bytes().len() as u8]);
        result.extend(self.to_bytes());
        Ok(result)
    }
}

impl TryInto<XRPLObject> for XRPLPaymentTx {
    type Error = ContractError;

    fn try_into(self) -> Result<XRPLObject, ContractError> {
        let mut obj = XRPLObject::new();
        obj.add_field(Field::TransactionType, &PAYMENT_TX_TYPE)?;
        obj.add_field(Field::Flags, &0u32)?;
        obj.add_sequence(&self.sequence)?;
        obj.add_field(Field::Amount, &self.amount)?;
        obj.add_field(Field::Fee, &XRPLPaymentAmount::Drops(self.fee))?;
        obj.add_field(Field::SigningPubKey, &HexBinary::from_hex("")?)?;
        obj.add_field(Field::Account, &self.account)?;
        obj.add_field(Field::Destination, &self.destination)?;

        let memo_data: Vec<u8> = self.multisig_session_id.to_be_bytes().iter().skip_while(|&&byte| byte == 0).cloned().collect();
        let memo = HexBinary::from_hex(hex::encode(memo_data).as_ref())?;
        obj.add_field(Field::Memos, &XRPLArray{field: Field::Memo, items: vec![XRPLMemo(memo)]})?;

        Ok(obj)
    }
}

impl TryInto<XRPLObject> for XRPLSignerListSetTx {
    type Error = ContractError;

    fn try_into(self) -> Result<XRPLObject, ContractError> {
        let mut obj = XRPLObject::new();

        obj.add_field(Field::TransactionType, &SIGNER_LIST_SET_TX_TYPE)?;
        obj.add_field(Field::Flags, &0u32)?; // flags
        obj.add_sequence(&self.sequence)?;
        obj.add_field(Field::SignerQuorum, &self.signer_quorum)?;
        obj.add_field(Field::Fee, &XRPLPaymentAmount::Drops(self.fee))?;
        obj.add_field(Field::Account, &self.account)?;
        obj.add_field(Field::SigningPubKey, &HexBinary::from_hex("")?)?;

        obj.add_field(Field::SignerEntries, &XRPLArray{ field: Field::SignerEntry, items: self.signer_entries.clone() })?;

        let memo_data: Vec<u8> = self.multisig_session_id.to_be_bytes().into_iter().skip_while(|&byte| byte == 0).collect();
        let memo = HexBinary::from_hex(hex::encode(memo_data).as_ref())?;
        obj.add_field(Field::Memos, &XRPLArray{field: Field::Memo, items: vec![XRPLMemo(memo)]})?;

        Ok(obj)
    }
}

impl TryInto<XRPLObject> for XRPLTicketCreateTx {
    type Error = ContractError;

    fn try_into(self) -> Result<XRPLObject, ContractError> {
        let mut obj = XRPLObject::new();
        obj.add_field(Field::TransactionType, &TICKET_CREATE_TX_TYPE)?;
        obj.add_field(Field::Flags, &0u32)?;
        obj.add_sequence(&self.sequence)?;
        obj.add_field(Field::TicketCount, &self.ticket_count)?;
        obj.add_field(Field::Fee, &XRPLPaymentAmount::Drops(self.fee))?;
        obj.add_field(Field::SigningPubKey, &HexBinary::from_hex("")?)?;
        obj.add_field(Field::Account, &self.account)?;

        let memo_data: Vec<u8> = self.multisig_session_id.to_be_bytes().into_iter().skip_while(|&byte| byte == 0).collect();
        let memo = HexBinary::from_hex(hex::encode(memo_data).as_ref())?;
        obj.add_field(Field::Memos, &XRPLArray{field: Field::Memo, items: vec![XRPLMemo(memo)]})?;

        Ok(obj)
    }
}

impl TryInto<XRPLObject> for XRPLUnsignedTx {
    type Error = ContractError;

    fn try_into(self) -> Result<XRPLObject, ContractError> {
        match self {
            XRPLUnsignedTx::Payment(tx) => tx.try_into(),
            XRPLUnsignedTx::TicketCreate(tx) => tx.try_into(),
            XRPLUnsignedTx::SignerListSet(tx) => tx.try_into()
        }
    }
}

impl TryInto<XRPLObject> for XRPLSignedTransaction {
    type Error = ContractError;

    fn try_into(self) -> Result<XRPLObject, ContractError> {
        let mut sorted_signers = self.signers.clone();
        sorted_signers.sort_by(|a, b| {
            // the Signers array must be sorted based on the numeric value of the signer addresses
            // https://xrpl.org/multi-signing.html#sending-multi-signed-transactions
            a.account.to_bytes().cmp(&b.account.to_bytes())
        });
        let mut obj: XRPLObject = self.unsigned_tx.clone().try_into()?;
        obj.add_field(Field::Signers, &XRPLArray{ field: Field::Signer, items: sorted_signers })?;
        Ok(obj)
    }
}

struct XRPLArray<T> {
    field: Field,
    items: Vec<T>
}

impl<T: XRPLSerialize> XRPLSerialize for XRPLArray<T> {
    const TYPE_CODE: u8 = 15;

    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError> {
        let mut result: Vec<u8> = Vec::new();
        for item in &self.items {
            result.extend(field_id(T::TYPE_CODE, self.field.clone().to_u8()));
            result.extend(item.xrpl_serialize()?);
            result.extend(field_id(T::TYPE_CODE, 1));
        }
        result.extend(field_id(Self::TYPE_CODE, 1));
        Ok(result)
    }
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

    pub fn add_field<T: XRPLSerialize>(&mut self, field: Field, value: &T) -> Result<(), ContractError> {
        self.fields.push((T::TYPE_CODE, field.to_u8(), value.xrpl_serialize()?));
        Ok(())
    }

    pub fn add_sequence(&mut self, sequence: &Sequence) -> Result<(), ContractError> {
        match sequence {
            Sequence::Plain(seq) => {
                self.add_field(Field::Sequence, seq)
            },
            Sequence::Ticket(seq) => {
                self.add_field(Field::Sequence, &0u32)?;
                self.add_field(Field::TicketSequence, seq)
            }
        }
    }
}

impl XRPLSerialize for XRPLObject {
    const TYPE_CODE: u8 = 14;

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

// Implementing XRPLSerialize for any type T that can be converted into XRPLObject
impl<T> XRPLSerialize for T
where
    T: TryInto<XRPLObject, Error = ContractError> + Clone,
{
    const TYPE_CODE: u8 = XRPLObject::TYPE_CODE;

    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError> {
        let obj: XRPLObject = self.clone().try_into()?;
        obj.xrpl_serialize()
    }
}

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

const MIN_MANTISSA: u64 = 1_000_000_000_000_000;
const MAX_MANTISSA: u64 = 10_000_000_000_000_000 - 1;
const MIN_EXPONENT: i64 = -96;
const MAX_EXPONENT: i64 = 80;

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

impl TryFrom<Uint128> for XRPLTokenAmount {
    type Error = ContractError;

    fn try_from(amount: Uint128) -> Result<XRPLTokenAmount, ContractError> {
        let (mantissa, exponent) = canonicalize_mantissa(amount)?;
        Ok(XRPLTokenAmount::new(mantissa, exponent))
    }
}

// always called when XRPLTokenAmount instantiated
// see https://github.com/XRPLF/xrpl-dev-portal/blob/82da0e53a8d6cdf2b94a80594541d868b4d03b94/content/_code-samples/tx-serialization/py/xrpl_num.py#L19
pub fn canonicalize_mantissa(mut mantissa: Uint128) -> Result<(u64, i64), ContractError> {
    let mut exponent = 0i64;

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

#[cfg(test)]
mod tests {
    use cosmwasm_std::{Uint128, Uint64};
    use multisig::key::PublicKey;

    use crate::types::XRPLToken;

    use super::*;

    #[macro_export]
    macro_rules! assert_hex_eq {
        ($expected:expr, $actual:expr) => {
            assert_eq!($expected, hex::encode_upper($actual));
        };
    }

    #[test]
    fn test_encode_length() -> Result<(), ContractError> {
        assert_hex_eq!("00", encode_length(0)?);
        assert_hex_eq!("0A", encode_length(10)?);
        assert_hex_eq!("C100", encode_length(193)?);
        assert_hex_eq!("F10000", encode_length(12481)?);
        assert_hex_eq!("FED417", encode_length(918744)?);
        assert!(encode_length(918745).is_err());
        Ok(())
    }

    #[test]
    fn test_xrpl_serialize() -> Result<(), ContractError> {
        assert_hex_eq!("0000", 0u16.xrpl_serialize()?);
        assert_hex_eq!("0001", 1u16.xrpl_serialize()?);
        assert_hex_eq!("FFFF", 0xffffu16.xrpl_serialize()?);
        assert_hex_eq!("00000000", 0u32.xrpl_serialize()?);
        assert_hex_eq!("00000005", 5u32.xrpl_serialize()?);
        assert_hex_eq!("FFFFFFFF", 0xffffffffu32.xrpl_serialize()?);
        assert_hex_eq!("00", HexBinary::from_hex("")?.xrpl_serialize()?);
        assert_hex_eq!("04DEADBEEF", HexBinary::from_hex("DEADBEEF")?.xrpl_serialize()?);
        assert_hex_eq!(
            "800000000000000000000000000000000000000055534400000000005B812C9D57731E27A2DA8B1830195F88EF32A3B6",
            XRPLPaymentAmount::Token(XRPLToken {
                issuer: "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ".try_into()?,
                currency: "USD".to_string(),
            }, Uint128::zero().try_into()?)
            .xrpl_serialize()?
        );
        assert_hex_eq!(
            "D4838D7EA4C6800000000000000000000000000055534400000000005B812C9D57731E27A2DA8B1830195F88EF32A3B6",
            XRPLPaymentAmount::Token(XRPLToken {
                issuer: "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ".try_into()?,
                currency: "USD".to_string(),
            }, Uint128::from(1u128).try_into()?)
            .xrpl_serialize()?
        );
        // minimum absolute amount
        assert_hex_eq!(
            "C0438D7EA4C6800000000000000000000000000055534400000000005B812C9D57731E27A2DA8B1830195F88EF32A3B6",
            XRPLPaymentAmount::Token(XRPLToken {
                issuer: "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ".try_into()?,
                currency: "USD".to_string(),
            }, XRPLTokenAmount { mantissa: MIN_MANTISSA, exponent: MIN_EXPONENT })
            .xrpl_serialize()?
        );
        // maximum amount
        assert_hex_eq!(
            "EC6386F26FC0FFFF00000000000000000000000055534400000000005B812C9D57731E27A2DA8B1830195F88EF32A3B6",
            XRPLPaymentAmount::Token(XRPLToken {
                issuer: "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ".try_into()?,
                currency: "USD".to_string(),
            }, XRPLTokenAmount { mantissa: MAX_MANTISSA, exponent: MAX_EXPONENT })
            .xrpl_serialize()?
        );
        // currency can contain non-alphanumeric ascii letters
        assert_hex_eq!(
            "D4CEEBE0B40E8000000000000000000000000000247B3B00000000005B812C9D57731E27A2DA8B1830195F88EF32A3B6",
            XRPLPaymentAmount::Token(XRPLToken {
                issuer: "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ".try_into()?,
                currency: "${;".to_string(),
            }, Uint128::from(42u128).try_into()?)
            .xrpl_serialize()?
        );
        // TODO: these could be enforced on a type level:
        //   - currency cannot contain non-ascii letters
        //   - currency must not be more than 3 ascii letters
        //   - currency must not be less than 3 ascii letters
        // XRP currency code is not allowed
        assert!(
            XRPLPaymentAmount::Token(XRPLToken {
                issuer: "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ".try_into()?,
                currency: "XRP".to_string(),
            }, Uint128::from(42u128).try_into()?)
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
            XRPLAccountId::try_from("rrrrrrrrrrrrrrrrrrrrrhoLvTp")?
            .xrpl_serialize()?
        );
        // account "1" (with length prefix)
        assert_hex_eq!(
            "140000000000000000000000000000000000000001",
            XRPLAccountId::try_from("rrrrrrrrrrrrrrrrrrrrBZbvji")?
            .xrpl_serialize()?
        );
        // max acccount
        assert_hex_eq!(
            "14FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            XRPLAccountId::try_from("rQLbzfJH5BT1FS9apRLKV3G8dWEA5njaQi")?
            .xrpl_serialize()?
        );
        assert_hex_eq!(
            "13000081140000000000000000000000000000000000000000",
            XRPLSignerEntry{
                account: "rrrrrrrrrrrrrrrrrrrrrhoLvTp".try_into()?,
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
            XRPLArray::<XRPLSignerEntry>{ field: Field::Memo, items: vec![] }
            .xrpl_serialize()?
        );
        // array with 1 element
        assert_hex_eq!(
            "EA13000081140000000000000000000000000000000000000000E1F1",
            XRPLArray::<XRPLSignerEntry>{ field: Field::Memo, items: vec![
                XRPLSignerEntry{
                    account: "rrrrrrrrrrrrrrrrrrrrrhoLvTp".try_into()?,
                    signer_weight: 0
                },
            ] }
            .xrpl_serialize()?
        );
        Ok(())
    }

    #[test]
    fn serialize_xrpl_unsigned_token_payment_transaction() -> Result<(), ContractError> {
        let unsigned_tx = XRPLPaymentTx {
            account: "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ".try_into()?,
            fee: 12,
            sequence: Sequence::Plain(1),
            amount: XRPLPaymentAmount::Token(
                XRPLToken {
                    currency: "JPY".to_string(),
                    issuer: "rrrrrrrrrrrrrrrrrrrrBZbvji".try_into()?,
                },
                XRPLTokenAmount { mantissa: 3369568318000000u64, exponent: -16 }
            ),
            destination: "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh".try_into()?,
            multisig_session_id: Uint64::from(1u8),
        };
        let encoded_unsigned_tx = XRPLUnsignedTx::Payment(unsigned_tx).xrpl_serialize()?;
        assert_eq!(
            "1200002200000000240000000161D44BF89AC2A40B800000000000000000000000004A50590000000000000000000000000000000000000000000000000168400000000000000C730081145B812C9D57731E27A2DA8B1830195F88EF32A3B68314B5F762798A53D543A014CAF8B297CFF8F2F937E8F9EA7D0101E1F1",
            hex::encode_upper(encoded_unsigned_tx)
        );
        Ok(())
    }

    #[test]
    fn serialize_xrpl_unsigned_xrp_payment_transaction() -> Result<(), ContractError> {
        let tx = XRPLPaymentTx {
            account: "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ".try_into()?,
            fee: 10,
            sequence: Sequence::Plain(1),
            amount: XRPLPaymentAmount::Drops(1000),
            destination: "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh".try_into()?,
            multisig_session_id: Uint64::from(0u8),
        };
        let encoded_unsigned_tx = &XRPLUnsignedTx::Payment(tx).xrpl_serialize()?;
        assert_eq!(
            "120000220000000024000000016140000000000003E868400000000000000A730081145B812C9D57731E27A2DA8B1830195F88EF32A3B68314B5F762798A53D543A014CAF8B297CFF8F2F937E8F9EA7D00E1F1",
            hex::encode_upper(encoded_unsigned_tx)
        );

        let tx = XRPLPaymentTx {
            account: "rhKnz85JUKcrAizwxNUDfqCvaUi9ZMhuwj".try_into()?,
            fee: 3,
            sequence: Sequence::Plain(43497363),
            amount: XRPLPaymentAmount::Drops(1000000000),
            destination: "rw2521mDNXyKzHBrFGZ5Rj4wzUjS9FbiZq".try_into()?,
            multisig_session_id: Uint64::from(1337u16),
        };
        let encoded_unsigned_tx = &XRPLUnsignedTx::Payment(tx).xrpl_serialize()?;
        assert_eq!(
            "1200002200000000240297B79361400000003B9ACA0068400000000000000373008114245409103F1B06F22FBCED389AAE0EFCE2F6689A83146919924835FA51D3991CDF5CF4505781227686E6F9EA7D020539E1F1",
            hex::encode_upper(encoded_unsigned_tx)
        );
        Ok(())
    }

    fn pub_key_from_hex(hex: &str) -> Result<PublicKey, ContractError> {
        Ok(PublicKey::Ecdsa(HexBinary::from_hex(hex)?))
    }

    #[test]
    fn serialize_xrpl_signed_xrp_payment_transaction() -> Result<(), ContractError> {
        let signed_tx = XRPLSignedTransaction {
            unsigned_tx: XRPLUnsignedTx::Payment(XRPLPaymentTx {
                account: "rfEf91bLxrTVC76vw1W3Ur8Jk4Lwujskmb".try_into()?,
                fee: 30,
                sequence: Sequence::Ticket(44218193),
                amount: XRPLPaymentAmount::Drops(100000000),
                destination: "rfgqgX62inhKsfti1NR6FeMS8NcQJCFniG".try_into()?,
                multisig_session_id: Uint64::from(5461264u64),
            }), signers: vec![
                XRPLSigner{
                    account: "r3mJFUQeVQma7qucT4iQSNCWuijVCPcicZ".try_into()?,
                    txn_signature: HexBinary::from_hex("3044022023DD4545108D411008FC9A76A58E1573AB0F8786413C8F38A92B1E2EAED60014022012A0A7890BFD0F0C8EA2C342107F65D4C91CAC29AAF3CF2840350BF3FB91E045")?,
                    signing_pub_key: pub_key_from_hex("025E0231BFAD810E5276E2CF9EB2F3F380CE0BDF6D84C3B6173499D3DDCC008856")?
                },
                XRPLSigner{
                    account: "rHxbKjRSFUUyuiio1jnFhimJRVAYYaGj7f".try_into()?,
                    txn_signature: HexBinary::from_hex("3045022100FC1490C236AD05A306EB5FD89072F14FEFC19ED35EB61BACD294D10E0910EDB102205A4CF0C0A759D7158A8FEE2F526C70277910DE88BF85564A1B3142AE635C9CE9")?,
                    signing_pub_key: pub_key_from_hex("036FF6F4B2BC5E08ABA924BD8FD986608F3685CA651A015B3D9D6A656DE14769FE")?
                }
            ],
        };
        let encoded_signed_tx = &signed_tx.xrpl_serialize()?;
        assert_eq!(
            "12000022000000002400000000202902A2B751614000000005F5E10068400000000000001E73008114447BB6E37CA4D5D89FC2E2470A64632DA9BDD9E4831449599D50E0C1AC0CFC8D3B2A30830F3738EACC3EF3E0107321025E0231BFAD810E5276E2CF9EB2F3F380CE0BDF6D84C3B6173499D3DDCC00885674463044022023DD4545108D411008FC9A76A58E1573AB0F8786413C8F38A92B1E2EAED60014022012A0A7890BFD0F0C8EA2C342107F65D4C91CAC29AAF3CF2840350BF3FB91E0458114552A0D8EFCF978186CA9C37112B502D3728DA9EFE1E0107321036FF6F4B2BC5E08ABA924BD8FD986608F3685CA651A015B3D9D6A656DE14769FE74473045022100FC1490C236AD05A306EB5FD89072F14FEFC19ED35EB61BACD294D10E0910EDB102205A4CF0C0A759D7158A8FEE2F526C70277910DE88BF85564A1B3142AE635C9CE98114BA058AB3573EA34DC934D60E719A12DE6C213DE2E1F1F9EA7D03535510E1F1",
            hex::encode_upper(encoded_signed_tx)
        );
        Ok(())
    }

    #[test]
    fn tx_serialization_sort_signers() -> Result<(), ContractError> {
        let signed_tx = XRPLSignedTransaction {
            unsigned_tx: XRPLUnsignedTx::Payment(XRPLPaymentTx {
                account: "rfEf91bLxrTVC76vw1W3Ur8Jk4Lwujskmb".try_into()?,
                fee: 30,
                sequence: Sequence::Ticket(44218193),
                amount: XRPLPaymentAmount::Drops(100000000),
                destination: "rfgqgX62inhKsfti1NR6FeMS8NcQJCFniG".try_into()?,
                multisig_session_id: Uint64::from(5461264u64),
            }), signers: vec![
                XRPLSigner{
                    account: "rHxbKjRSFUUyuiio1jnFhimJRVAYYaGj7f".try_into()?,
                    txn_signature: HexBinary::from_hex("3045022100FC1490C236AD05A306EB5FD89072F14FEFC19ED35EB61BACD294D10E0910EDB102205A4CF0C0A759D7158A8FEE2F526C70277910DE88BF85564A1B3142AE635C9CE9")?,
                    signing_pub_key: pub_key_from_hex("036FF6F4B2BC5E08ABA924BD8FD986608F3685CA651A015B3D9D6A656DE14769FE")?
                },
                XRPLSigner{
                    account: "r3mJFUQeVQma7qucT4iQSNCWuijVCPcicZ".try_into()?,
                    txn_signature: HexBinary::from_hex("3044022023DD4545108D411008FC9A76A58E1573AB0F8786413C8F38A92B1E2EAED60014022012A0A7890BFD0F0C8EA2C342107F65D4C91CAC29AAF3CF2840350BF3FB91E045")?,
                    signing_pub_key: pub_key_from_hex("025E0231BFAD810E5276E2CF9EB2F3F380CE0BDF6D84C3B6173499D3DDCC008856")?
                },
            ],
        };
        let encoded_signed_tx = &signed_tx.xrpl_serialize()?;
        assert_eq!(
            "12000022000000002400000000202902A2B751614000000005F5E10068400000000000001E73008114447BB6E37CA4D5D89FC2E2470A64632DA9BDD9E4831449599D50E0C1AC0CFC8D3B2A30830F3738EACC3EF3E0107321025E0231BFAD810E5276E2CF9EB2F3F380CE0BDF6D84C3B6173499D3DDCC00885674463044022023DD4545108D411008FC9A76A58E1573AB0F8786413C8F38A92B1E2EAED60014022012A0A7890BFD0F0C8EA2C342107F65D4C91CAC29AAF3CF2840350BF3FB91E0458114552A0D8EFCF978186CA9C37112B502D3728DA9EFE1E0107321036FF6F4B2BC5E08ABA924BD8FD986608F3685CA651A015B3D9D6A656DE14769FE74473045022100FC1490C236AD05A306EB5FD89072F14FEFC19ED35EB61BACD294D10E0910EDB102205A4CF0C0A759D7158A8FEE2F526C70277910DE88BF85564A1B3142AE635C9CE98114BA058AB3573EA34DC934D60E719A12DE6C213DE2E1F1F9EA7D03535510E1F1",
            hex::encode_upper(encoded_signed_tx)
        );
        Ok(())
    }

    #[test]
    fn tx_serialization_ed25519_signers() -> Result<(), ContractError> {
        let signed_tx = XRPLSignedTransaction {
            unsigned_tx: XRPLUnsignedTx::Payment(XRPLPaymentTx {
                account: "r4ZMbbb4Y3KoeexmjEeTdhqUBrYjjWdyGM".try_into()?,
                fee: 30,
                sequence: Sequence::Ticket(45205896),
                amount: XRPLPaymentAmount::Token(XRPLToken{ currency: "ETH".to_string(), issuer: "r4ZMbbb4Y3KoeexmjEeTdhqUBrYjjWdyGM".try_into()? }, Uint128::from(100000000u128).try_into()?),
                destination: "raNVNWvhUQzFkDDTdEw3roXRJfMJFVJuQo".try_into()?,
                multisig_session_id: Uint64::from(5461264u64),
            }), signers: vec![
                XRPLSigner{
                    account: "rBTmbPMAWghUv52pCCtkLYh5SPVy2PuDSj".try_into()?,
                    txn_signature: HexBinary::from_hex("531B9E854C81AEFA573C00DF1603C3DE80C1F3680D39A80F3FB725A0388D177E3EC5E28AD6760D9EEF8203FEB1FC61F9D9451F777114B97943E5702B54589E09")?,
                    signing_pub_key: PublicKey::Ed25519(HexBinary::from_hex("45e67eaf446e6c26eb3a2b55b64339ecf3a4d1d03180bee20eb5afdd23fa644f")?)
                },
                XRPLSigner{
                    account: "rhAdaMDgF89314TfNRHc5GsA6LQZdk35S5".try_into()?,
                    txn_signature: HexBinary::from_hex("76CF2097D7038B90445CB952AE52CBDBE6D55FE7C0562493FE3D9AAE5E05A66A43777CBCDAA89233CAFD4D1D0F9B02DB0619B9BB14957CC3ADAA8D7D343E0106")?,
                    signing_pub_key: PublicKey::Ed25519(HexBinary::from_hex("dd9822c7fa239dda9913ebee813ecbe69e35d88ff651548d5cc42c033a8a667b")?)
                },
            ],
        };
        let encoded_signed_tx = &signed_tx.xrpl_serialize()?;
        assert_eq!(
            "12000022000000002400000000202902B1C98861D6838D7EA4C680000000000000000000000000004554480000000000EC792533BC26024CFAA5DDC2D04128E59581309C68400000000000001E73008114EC792533BC26024CFAA5DDC2D04128E59581309C831439659AAAD4DC8603798352FCF954419A67977536F3E0107321EDDD9822C7FA239DDA9913EBEE813ECBE69E35D88FF651548D5CC42C033A8A667B744076CF2097D7038B90445CB952AE52CBDBE6D55FE7C0562493FE3D9AAE5E05A66A43777CBCDAA89233CAFD4D1D0F9B02DB0619B9BB14957CC3ADAA8D7D343E010681142B3CF7B1986F5CB4EFEF11F933F40EC3106412C2E1E0107321ED45E67EAF446E6C26EB3A2B55B64339ECF3A4D1D03180BEE20EB5AFDD23FA644F7440531B9E854C81AEFA573C00DF1603C3DE80C1F3680D39A80F3FB725A0388D177E3EC5E28AD6760D9EEF8203FEB1FC61F9D9451F777114B97943E5702B54589E09811472C14C0DB6CEF64A87CC3D152D7B0E917D372BE7E1F1F9EA7D03535510E1F1",
            hex::encode_upper(encoded_signed_tx)
        );
        Ok(())
    }


    #[test]
    fn serialize_xrpl_signed_xrp_ticket_create_transaction() -> Result<(), ContractError> {
        let signed_tx = XRPLSignedTransaction {
            unsigned_tx: XRPLUnsignedTx::TicketCreate(XRPLTicketCreateTx {
                account: "rfEf91bLxrTVC76vw1W3Ur8Jk4Lwujskmb".try_into()?,
                fee: 30,
                sequence: Sequence::Plain(44218194),
                ticket_count: 3,
                multisig_session_id: Uint64::from(5461264u64),
            }), signers: vec![
                XRPLSigner{
                    account: "r3mJFUQeVQma7qucT4iQSNCWuijVCPcicZ".try_into()?,
                    txn_signature: HexBinary::from_hex("304402203C10D5295AE4A34FD702355B075E951CF9FFE3A73F8B7557FB68E5DF64D87D3702200945D65BAAD7F10A14EA57E08914005F412709D10F27D868D63BE3052F30363F")?,
                    signing_pub_key: pub_key_from_hex("025E0231BFAD810E5276E2CF9EB2F3F380CE0BDF6D84C3B6173499D3DDCC008856")?
                },
                XRPLSigner{
                    account: "rHxbKjRSFUUyuiio1jnFhimJRVAYYaGj7f".try_into()?,
                    txn_signature: HexBinary::from_hex("3045022100EF2CBAC3B2D81E1E3502B064BA198D9D0D3F1FFE6604DAC5019C53C262B5F9E7022000808A438BD5CA808649DCDA6766D2BA0E8FA7E94150675F73FC41B2F73C9C58")?,
                    signing_pub_key: pub_key_from_hex("036FF6F4B2BC5E08ABA924BD8FD986608F3685CA651A015B3D9D6A656DE14769FE")?
                },
            ]
        };
        let encoded_signed_tx = signed_tx.xrpl_serialize()?;
        assert_eq!(
            "12000A22000000002402A2B75220280000000368400000000000001E73008114447BB6E37CA4D5D89FC2E2470A64632DA9BDD9E4F3E0107321025E0231BFAD810E5276E2CF9EB2F3F380CE0BDF6D84C3B6173499D3DDCC0088567446304402203C10D5295AE4A34FD702355B075E951CF9FFE3A73F8B7557FB68E5DF64D87D3702200945D65BAAD7F10A14EA57E08914005F412709D10F27D868D63BE3052F30363F8114552A0D8EFCF978186CA9C37112B502D3728DA9EFE1E0107321036FF6F4B2BC5E08ABA924BD8FD986608F3685CA651A015B3D9D6A656DE14769FE74473045022100EF2CBAC3B2D81E1E3502B064BA198D9D0D3F1FFE6604DAC5019C53C262B5F9E7022000808A438BD5CA808649DCDA6766D2BA0E8FA7E94150675F73FC41B2F73C9C588114BA058AB3573EA34DC934D60E719A12DE6C213DE2E1F1F9EA7D03535510E1F1",
            hex::encode_upper(encoded_signed_tx)
        );
        Ok(())
    }

    #[test]
    fn serialize_xrpl_signed_signer_list_set_transaction() -> Result<(), ContractError> {
        let signed_tx = XRPLSignedTransaction {
            unsigned_tx: XRPLUnsignedTx::SignerListSet(XRPLSignerListSetTx {
                account: "rfEf91bLxrTVC76vw1W3Ur8Jk4Lwujskmb".try_into()?,
                fee: 30,
                sequence: Sequence::Plain(44218445),
                signer_quorum: 3,
                signer_entries: vec![
                    XRPLSignerEntry{
                        account: "r3mJFUQeVQma7qucT4iQSNCWuijVCPcicZ".try_into()?,
                        signer_weight: 2
                    },
                    XRPLSignerEntry{
                        account: "rHxbKjRSFUUyuiio1jnFhimJRVAYYaGj7f".try_into()?,
                        signer_weight: 1
                    }
                ],
                multisig_session_id: Uint64::from(5461264u64)
            }), signers: vec![
                XRPLSigner{
                    account: "r3mJFUQeVQma7qucT4iQSNCWuijVCPcicZ".try_into()?,
                    txn_signature: HexBinary::from_hex("3045022100B94B346A418BE9EF5AEE7806EE984E3E9B48EB4ED48E79B5BFB69C607167023E02206B14BD72B69206D14DADA82ACCDD2539D275719FB187ECE2A46BAC9025877B39")?,
                    signing_pub_key: pub_key_from_hex("025E0231BFAD810E5276E2CF9EB2F3F380CE0BDF6D84C3B6173499D3DDCC008856")?,
                },
                XRPLSigner{
                    account: "rHxbKjRSFUUyuiio1jnFhimJRVAYYaGj7f".try_into()?,
                    txn_signature: HexBinary::from_hex("3044022072A1028FF972D9D6E950810AF72443EEE352ADB1BC54B1112983842C857C464502206D74A77387979A47863F08F9191611D142C2BD6B32D5C750EF58513C5669F21A")?,
                    signing_pub_key: pub_key_from_hex("036FF6F4B2BC5E08ABA924BD8FD986608F3685CA651A015B3D9D6A656DE14769FE")?,
                },
            ],
        };
        let encoded_signed_tx = signed_tx.xrpl_serialize()?;
        assert_eq!(
            "12000C22000000002402A2B84D20230000000368400000000000001E73008114447BB6E37CA4D5D89FC2E2470A64632DA9BDD9E4F3E0107321025E0231BFAD810E5276E2CF9EB2F3F380CE0BDF6D84C3B6173499D3DDCC00885674473045022100B94B346A418BE9EF5AEE7806EE984E3E9B48EB4ED48E79B5BFB69C607167023E02206B14BD72B69206D14DADA82ACCDD2539D275719FB187ECE2A46BAC9025877B398114552A0D8EFCF978186CA9C37112B502D3728DA9EFE1E0107321036FF6F4B2BC5E08ABA924BD8FD986608F3685CA651A015B3D9D6A656DE14769FE74463044022072A1028FF972D9D6E950810AF72443EEE352ADB1BC54B1112983842C857C464502206D74A77387979A47863F08F9191611D142C2BD6B32D5C750EF58513C5669F21A8114BA058AB3573EA34DC934D60E719A12DE6C213DE2E1F1F4EB1300028114552A0D8EFCF978186CA9C37112B502D3728DA9EFE1EB1300018114BA058AB3573EA34DC934D60E719A12DE6C213DE2E1F1F9EA7D03535510E1F1",
            hex::encode_upper(encoded_signed_tx)
        );
        Ok(())
    }

}