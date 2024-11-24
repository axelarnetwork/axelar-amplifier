use std::cmp::Ordering;

use cosmwasm_std::HexBinary;
use multisig::key::PublicKey;
use xrpl_types::types::{
    XRPLAccountId, XRPLMemo, XRPLPathSet, XRPLSignedTransaction,
    XRPLPathStep, XRPLPaymentAmount, XRPLSequence, XRPLSigner, XRPLSignerEntry,
    XRPLTokenAmount, XRPLUnsignedTx, XRPLPaymentTx, XRPLSignerListSetTx, XRPLTicketCreateTx,
    XRPLTrustSetTx,
};

use crate::error::ContractError;

const PAYMENT_TX_TYPE: u16 = 0;
const TICKET_CREATE_TX_TYPE: u16 = 10;
const SIGNER_LIST_SET_TX_TYPE: u16 = 12;
const TRUST_SET_TX_TYPE: u16 = 20;

const POSITIVE_BIT: u64 = 0x4000000000000000;

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
    Signer,
    LimitAmount,
    SendMax,
    Paths
}

impl Field {
    const fn to_u8(&self) -> u8 {
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
            Field::Signer => 16,
            Field::LimitAmount => 3,
            Field::SendMax => 9,
            Field::Paths => 1
        }
    }
}

use Field::*;

#[macro_export]
macro_rules! xrpl_json {
    // Match a JSON-like structure.
    ({ $($key:ident: $value:expr),* $(,)? }) => {{
        let mut obj = XRPLObject::new();

        // Process each key-value pair.
        $(
            obj.add_field($key, $value)?;
        )*

        obj
    }};
}

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
            &XRPLPaymentAmount::Drops(value) => {
                if value <= 10u64.pow(17) {
                    Ok((value | POSITIVE_BIT).to_be_bytes().to_vec())
                } else {
                    Err(ContractError::InvalidAmount {
                        reason: "more than maximum amount of drops".to_string(),
                    })
                }
            }
            XRPLPaymentAmount::Issued(token, amount) => {
                let mut buf = Vec::with_capacity(48);
                buf.extend_from_slice(&amount.to_bytes());
                buf.extend_from_slice(&token.currency.clone().to_bytes());
                buf.extend_from_slice(token.issuer.as_ref());
                Ok(buf)
            }
        }
    }
}

impl XRPLSerialize for HexBinary {
    const TYPE_CODE: u8 = 7;

    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError> {
        let len_encoded = encode_length(self.len())?;
        let contents = self.to_vec();
        let mut result = Vec::with_capacity(len_encoded.len() + contents.len());
        result.extend(len_encoded);
        result.extend(contents);
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
    } else if length <= 918744 {
        length -= 12481;
        Ok(vec![
            241 + (length >> 16) as u8,
            ((length >> 8) & 0xff) as u8,
            (length & 0xff) as u8,
        ])
    } else {
        Err(ContractError::InvalidBlobLength)
    }
}

impl XRPLSerialize for PublicKey {
    const TYPE_CODE: u8 = 7;
    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError> {
        match self.clone() {
            // rippled prefixes Ed25519 public keys with the byte 0xED so both types of public key are 33 bytes.
            // https://xrpl.org/cryptographic-keys.html
            Self::Ed25519(hex) => {
                HexBinary::from_hex(format!("ED{}", hex.to_hex()).as_str())?.xrpl_serialize()
            }
            Self::Ecdsa(hex) => hex.xrpl_serialize(),
        }
    }
}

impl TryInto<XRPLObject> for XRPLSigner {
    type Error = ContractError;

    fn try_into(self) -> Result<XRPLObject, ContractError> {
        Ok(xrpl_json!({
            SigningPubKey: self.signing_pub_key,
            TxnSignature: self.txn_signature,
            Account: self.account
        }))
    }
}

impl TryInto<XRPLObject> for XRPLSignerEntry {
    type Error = ContractError;

    fn try_into(self) -> Result<XRPLObject, ContractError> {
        Ok(xrpl_json!({
            Account: self.account,
            SignerWeight: self.signer_weight
        }))
    }
}


impl TryInto<XRPLObject> for XRPLMemo {
    type Error = ContractError;

    fn try_into(self) -> Result<XRPLObject, ContractError> {
        Ok(xrpl_json!({
            MemoData: self.0
        }))
    }
}

impl XRPLSerialize for XRPLAccountId {
    const TYPE_CODE: u8 = 8;

    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError> {
        let mut result: Vec<u8> = Vec::new();
        result.extend(vec![20u8]);
        result.extend(self.to_bytes());
        Ok(result)
    }
}

impl XRPLSerialize for XRPLPathSet {
    const TYPE_CODE: u8 = 18;

    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError> {
        assert!(self.paths.len() > 0);
        assert!(self.paths.len() <= 6);
        let mut result: Vec<u8> = Vec::new();
        for (i, path) in self.paths.iter().enumerate() {
            assert!(path.steps.len() > 0);
            assert!(path.steps.len() <= 8);
            for step in path.steps.iter() {
                let (type_flag, first_value, opt_second_value): (u8, [u8; 20], Option<[u8; 20]>) = match step {
                    XRPLPathStep::Account(account) => (0x01, account.to_bytes(), None),
                    XRPLPathStep::Currency(currency) => (0x10, currency.clone().to_bytes(), None),
                    XRPLPathStep::XRP => (0x10, <[u8; 20]>::default(), None),
                    XRPLPathStep::Issuer(issuer) => (0x20, issuer.to_bytes(), None),
                    XRPLPathStep::Token(token) => (0x30, token.currency.clone().to_bytes(), Some(token.issuer.to_bytes())),
                };
                result.extend(vec![type_flag]);
                result.extend(first_value);
                if let Some(second_value) = opt_second_value {
                    result.extend(second_value);
                }
            }
            if i != self.paths.len() - 1 {
                result.extend(vec![0xff]); // "continue"
            } else {
                result.extend(vec![0x00]); // "end"
            }
        }
        Ok(result)
    }
}

/*
fn hex_encode_session_id(session_id: Uint64) -> HexBinary {
    HexBinary::from(session_id
        .to_be_bytes()
        .iter()
        .skip_while(|&&byte| byte == 0)
        .cloned()
        .collect::<Vec<u8>>(),
    )
}
*/

impl TryInto<XRPLObject> for XRPLPaymentTx {
    type Error = ContractError;

    fn try_into(self) -> Result<XRPLObject, ContractError> {
        let mut obj = xrpl_json!({
            TransactionType: PAYMENT_TX_TYPE,
            Flags: 0u32,
            Amount: self.amount,
            Fee: XRPLPaymentAmount::Drops(self.fee),
            Account: self.account,
            SigningPubKey: HexBinary::from(vec![]),
            Destination: self.destination,
        });
        obj.add_sequence(self.sequence)?;
        if let Some(cross_currency) = self.cross_currency {
            obj.add_field(Field::SendMax, cross_currency.send_max)?;
            if let Some(paths) = cross_currency.paths {
                obj.add_field(Field::Paths, paths)?;
            }
        }
        Ok(obj)
    }
}

impl TryInto<XRPLObject> for XRPLSignerListSetTx {
    type Error = ContractError;

    fn try_into(self) -> Result<XRPLObject, ContractError> {
        let mut obj = xrpl_json!({
            TransactionType: SIGNER_LIST_SET_TX_TYPE,
            Flags: 0u32,
            SignerQuorum: self.signer_quorum,
            Fee: XRPLPaymentAmount::Drops(self.fee),
            Account: self.account,
            SigningPubKey: HexBinary::from(vec![]),
            SignerEntries: XRPLArray{ field: Field::SignerEntry, items: self.signer_entries.clone() },
        });
        obj.add_sequence(self.sequence)?;
        Ok(obj)
    }
}

impl TryInto<XRPLObject> for XRPLTicketCreateTx {
    type Error = ContractError;

    fn try_into(self) -> Result<XRPLObject, ContractError> {
        let mut obj = xrpl_json!({
            TransactionType: TICKET_CREATE_TX_TYPE,
            Flags: 0u32,
            TicketCount: self.ticket_count,
            Fee: XRPLPaymentAmount::Drops(self.fee),
            Account: self.account,
            SigningPubKey: HexBinary::from(vec![]),
        });
        obj.add_sequence(self.sequence)?;
        Ok(obj)
    }
}

impl TryInto<XRPLObject> for XRPLTrustSetTx {
    type Error = ContractError;

    fn try_into(self) -> Result<XRPLObject, ContractError> {
        let mut obj = xrpl_json!({
            TransactionType: TRUST_SET_TX_TYPE,
            Flags: 0u32,
            LimitAmount: XRPLPaymentAmount::Issued(self.token, XRPLTokenAmount::MAX),
            Fee: XRPLPaymentAmount::Drops(self.fee),
            Account: self.account,
            SigningPubKey: HexBinary::from(vec![]),
        });
        obj.add_sequence(self.sequence)?;
        Ok(obj)
    }
}

impl TryInto<XRPLObject> for XRPLUnsignedTx {
    type Error = ContractError;

    fn try_into(self) -> Result<XRPLObject, ContractError> {
        match self {
            XRPLUnsignedTx::Payment(tx) => tx.try_into(),
            XRPLUnsignedTx::TicketCreate(tx) => tx.try_into(),
            XRPLUnsignedTx::SignerListSet(tx) => tx.try_into(),
            XRPLUnsignedTx::TrustSet(tx) => tx.try_into(),
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
            a.account.as_ref().cmp(&b.account.as_ref())
        });
        let mut obj: XRPLObject = self.unsigned_tx.clone().try_into()?;
        obj.add_field(
            Field::Signers,
            XRPLArray {
                field: Field::Signer,
                items: sorted_signers,
            },
        )?;
        Ok(obj)
    }
}

struct XRPLArray<T> {
    field: Field,
    items: Vec<T>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct SerializedField {
    type_code: u8,
    field_code: u8,
    serialized_value: Vec<u8>,
}

impl SerializedField {
    fn new(type_code: u8, field_code: u8, serialized_value: Vec<u8>) -> Self {
        Self {
            type_code,
            field_code,
            serialized_value,
        }
    }
}

impl PartialOrd for SerializedField {
    fn partial_cmp(&self, other: &SerializedField) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SerializedField {
    fn cmp(&self, other: &SerializedField) -> Ordering {
        (self.type_code, self.field_code).cmp(&(other.type_code, other.field_code))
    }
}

#[derive(Debug, Clone, Default)]
pub struct XRPLObject {
    fields: Vec<SerializedField>,
}

impl XRPLObject {
    pub fn new() -> XRPLObject {
        Self { fields: Vec::new() }
    }

    pub fn add_field<T: XRPLSerialize>(
        &mut self,
        field: Field,
        value: T,
    ) -> Result<(), ContractError> {
        self.fields.push(SerializedField::new(
            T::TYPE_CODE,
            field.to_u8(),
            value.xrpl_serialize()?,
        ));
        Ok(())
    }

    pub fn add_sequence(&mut self, sequence: XRPLSequence) -> Result<(), ContractError> {
        match sequence {
            XRPLSequence::Plain(seq) => self.add_field(Field::Sequence, seq),
            XRPLSequence::Ticket(seq) => {
                self.add_field(Field::Sequence, 0u32)?;
                self.add_field(Field::TicketSequence, seq)
            }
        }
    }
}

impl XRPLSerialize for XRPLObject {
    const TYPE_CODE: u8 = 14;

    fn xrpl_serialize(&self) -> Result<Vec<u8>, ContractError> {
        let mut fields: Vec<SerializedField> = self.fields.clone();
        fields.sort();
        let mut buf = Vec::new();
        for field in fields {
            buf.extend(field_id(field.type_code, field.field_code));
            buf.extend(field.serialized_value);
        }
        Ok(buf)
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
fn field_id(type_code: u8, field_code: u8) -> Vec<u8> {
    if type_code < 16 {
        if field_code < 16 {
            vec![type_code << 4 | field_code]
        } else {
            vec![type_code << 4, field_code]
        }
    } else {
        if field_code < 16 {
            vec![field_code, type_code]
        } else {
            vec![0, type_code, field_code]
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use cosmwasm_std::Uint128;
    use multisig::key::PublicKey;

    use xrpl_types::types::{canonicalize_coin_amount, XRPLCrossCurrencyOptions, XRPLCurrency, XRPLPath, XRPLToken, XRPL_TOKEN_MAX_EXPONENT, XRPL_TOKEN_MAX_MANTISSA, XRPL_TOKEN_MIN_EXPONENT, XRPL_TOKEN_MIN_MANTISSA};

    use super::*;

    #[macro_export]
    macro_rules! assert_hex_eq {
        ($expected:expr, $actual:expr) => {
            assert_eq!(
                HexBinary::from_hex($expected).unwrap(),
                HexBinary::from($actual.as_slice()),
            );
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
        assert_hex_eq!(
            "04DEADBEEF",
            HexBinary::from_hex("DEADBEEF")?.xrpl_serialize()?
        );
        assert_hex_eq!(
            "800000000000000000000000000000000000000055534400000000005B812C9D57731E27A2DA8B1830195F88EF32A3B6",
            XRPLPaymentAmount::Issued(XRPLToken {
                issuer: XRPLAccountId::from_str("r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ")?,
                currency: "USD".to_string().try_into()?,
            }, canonicalize_coin_amount(Uint128::zero(), 0)?)
            .xrpl_serialize()?
        );
        assert_hex_eq!(
            "D4838D7EA4C6800000000000000000000000000055534400000000005B812C9D57731E27A2DA8B1830195F88EF32A3B6",
            XRPLPaymentAmount::Issued(XRPLToken {
                issuer: XRPLAccountId::from_str("r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ")?,
                currency: "USD".to_string().try_into()?,
            }, canonicalize_coin_amount(Uint128::one(), 0)?)
            .xrpl_serialize()?
        );
        // minimum absolute amount
        assert_hex_eq!(
            "C0438D7EA4C6800000000000000000000000000055534400000000005B812C9D57731E27A2DA8B1830195F88EF32A3B6",
            XRPLPaymentAmount::Issued(XRPLToken {
                issuer: XRPLAccountId::from_str("r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ")?,
                currency: "USD".to_string().try_into()?
            }, XRPLTokenAmount::new(XRPL_TOKEN_MIN_MANTISSA, XRPL_TOKEN_MIN_EXPONENT))
            .xrpl_serialize()?
        );
        // maximum amount
        assert_hex_eq!(
            "EC6386F26FC0FFFF00000000000000000000000055534400000000005B812C9D57731E27A2DA8B1830195F88EF32A3B6",
            XRPLPaymentAmount::Issued(XRPLToken {
                issuer: XRPLAccountId::from_str("r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ")?,
                currency: "USD".to_string().try_into()?
            }, XRPLTokenAmount::new(XRPL_TOKEN_MAX_MANTISSA, XRPL_TOKEN_MAX_EXPONENT))
            .xrpl_serialize()?
        );
        // currency cannot contain certain characters like ";"
        assert!(XRPLCurrency::try_from("${;".to_string()).is_err());
        assert!(XRPLCurrency::try_from("XRP".to_string()).is_err());
        // currency can contain non-alphanumeric ascii letters
        assert_hex_eq!(
            "D4CEEBE0B40E8000000000000000000000000000247B7D00000000005B812C9D57731E27A2DA8B1830195F88EF32A3B6",
            XRPLPaymentAmount::Issued(XRPLToken {
                issuer: XRPLAccountId::from_str("r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ")?,
                currency: "${}".to_string().try_into()?,
            }, canonicalize_coin_amount(Uint128::from(42u128), 0)?)
            .xrpl_serialize()?
        );
        // minimum XRP
        assert_hex_eq!(
            "4000000000000000",
            XRPLPaymentAmount::Drops(0).xrpl_serialize()?
        );
        assert_hex_eq!(
            "4000000000000001",
            XRPLPaymentAmount::Drops(1).xrpl_serialize()?
        );
        assert_hex_eq!(
            "40000000499602D2",
            XRPLPaymentAmount::Drops(1234567890).xrpl_serialize()?
        );
        // maximum XRP
        assert_hex_eq!(
            "416345785D8A0000",
            XRPLPaymentAmount::Drops(100_000_000_000_000_000).xrpl_serialize()?
        );
        // more than maximum XRP fails
        assert!(XRPLPaymentAmount::Drops(100_000_000_000_000_001)
            .xrpl_serialize()
            .is_err());
        // account "0" (with length prefix)
        assert_hex_eq!(
            "140000000000000000000000000000000000000000",
            XRPLAccountId::from_str("rrrrrrrrrrrrrrrrrrrrrhoLvTp")?.xrpl_serialize()?
        );
        // account "1" (with length prefix)
        assert_hex_eq!(
            "140000000000000000000000000000000000000001",
            XRPLAccountId::from_str("rrrrrrrrrrrrrrrrrrrrBZbvji")?.xrpl_serialize()?
        );
        // max acccount
        assert_hex_eq!(
            "14FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            XRPLAccountId::from_str("rQLbzfJH5BT1FS9apRLKV3G8dWEA5njaQi")?.xrpl_serialize()?
        );
        assert_hex_eq!(
            "13000081140000000000000000000000000000000000000000",
            XRPLSignerEntry {
                account: XRPLAccountId::from_str("rrrrrrrrrrrrrrrrrrrrrhoLvTp")?,
                signer_weight: 0
            }
            .xrpl_serialize()?
        );
        // { "NetworkID": 0 }
        assert_hex_eq!(
            "2100000000",
            XRPLObject {
                fields: vec![SerializedField::new(2, 1, 0u32.xrpl_serialize()?)]
            }
            .xrpl_serialize()?
        );
        // empty array
        assert_hex_eq!(
            "F1",
            XRPLArray::<XRPLSignerEntry> {
                field: Field::Memo,
                items: vec![]
            }
            .xrpl_serialize()?
        );
        // array with 1 element
        assert_hex_eq!(
            "EA13000081140000000000000000000000000000000000000000E1F1",
            XRPLArray::<XRPLSignerEntry> {
                field: Field::Memo,
                items: vec![XRPLSignerEntry {
                    account: XRPLAccountId::from_str("rrrrrrrrrrrrrrrrrrrrrhoLvTp")?,
                    signer_weight: 0
                },]
            }
            .xrpl_serialize()?
        );
        assert_hex_eq!(
            "01000000000000000000000000000000000000000100",
            XRPLPathSet {
                paths: vec![
                    XRPLPath {
                        steps: vec![XRPLPathStep::Account(
                            XRPLAccountId::from_str("rrrrrrrrrrrrrrrrrrrrBZbvji").unwrap()
                        )]
                    }
                ]
            }.xrpl_serialize()?
        );
        assert_hex_eq!(
            "20000000000000000000000000000000000000000100",
            XRPLPathSet {
                paths: vec![
                    XRPLPath {
                        steps: vec![XRPLPathStep::Issuer(
                            XRPLAccountId::from_str("rrrrrrrrrrrrrrrrrrrrBZbvji").unwrap()
                        )]
                    }
                ]
            }.xrpl_serialize()?
        );
        assert_hex_eq!(
            "10000000000000000000000000000000000000000000",
            XRPLPathSet {
                paths: vec![
                    XRPLPath {
                        steps: vec![XRPLPathStep::XRP]
                    }
                ]
            }.xrpl_serialize()?
        );
        assert_hex_eq!(
            "10000000000000000000000000555344000000000000",
            XRPLPathSet {
                paths: vec![
                    XRPLPath {
                        steps: vec![XRPLPathStep::Currency(
                            "USD".to_string().try_into().unwrap()
                        )]
                    }
                ]
            }.xrpl_serialize()?
        );
        assert_hex_eq!(
            "300000000000000000000000005553440000000000000000000000000000000000000000000000000100",
            XRPLPathSet {
                paths: vec![
                    XRPLPath {
                        steps: vec![XRPLPathStep::Token(
                            XRPLToken {
                                issuer: XRPLAccountId::from_str("rrrrrrrrrrrrrrrrrrrrBZbvji")?,
                                currency: "USD".to_string().try_into()?,
                            }
                        )]
                    }
                ]
            }.xrpl_serialize()?
        );
        assert_hex_eq!(
            "100000000000000000000000000000000000000000010000000000000000000000000000000000000001FF100000000000000000000000004555520000000000300000000000000000000000005553440000000000000000000000000000000000000000000000000100",
            XRPLPathSet {
                paths: vec![
                    XRPLPath {
                        steps: vec![
                            XRPLPathStep::XRP,
                            XRPLPathStep::Account(
                                XRPLAccountId::from_str("rrrrrrrrrrrrrrrrrrrrBZbvji")?,
                            )
                        ]
                    },
                    XRPLPath {
                        steps: vec![
                            XRPLPathStep::Currency(
                                "EUR".to_string().try_into()?
                            ),
                            XRPLPathStep::Token(
                                XRPLToken {
                                    issuer: XRPLAccountId::from_str("rrrrrrrrrrrrrrrrrrrrBZbvji")?,
                                    currency: "USD".to_string().try_into()?,
                                }
                            ),
                        ]
                    }
                ]
            }.xrpl_serialize()?
        );

        Ok(())
    }

    #[test]
    fn serialize_xrpl_unsigned_token_payment_transaction() -> Result<(), ContractError> {
        let unsigned_tx = XRPLPaymentTx {
            account: XRPLAccountId::from_str("r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ")?,
            fee: 12,
            sequence: XRPLSequence::Plain(1),
            amount: XRPLPaymentAmount::Issued(
                XRPLToken {
                    currency: "JPY".to_string().try_into()?,
                    issuer: XRPLAccountId::from_str("rrrrrrrrrrrrrrrrrrrrBZbvji")?,
                },
                XRPLTokenAmount::new(3369568318000000u64, -16),
            ),
            destination: XRPLAccountId::from_str("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh")?,
            cross_currency: None
        };
        let encoded_unsigned_tx = XRPLUnsignedTx::Payment(unsigned_tx).xrpl_serialize()?;
        assert_hex_eq!(
            "1200002200000000240000000161D44BF89AC2A40B800000000000000000000000004A50590000000000000000000000000000000000000000000000000168400000000000000C730081145B812C9D57731E27A2DA8B1830195F88EF32A3B68314B5F762798A53D543A014CAF8B297CFF8F2F937E8",
            encoded_unsigned_tx
        );
        Ok(())
    }

    #[test]
    fn serialize_cross_currency_payment_transaction() -> Result<(), ContractError> {
        let unsigned_tx = XRPLPaymentTx {
            account: XRPLAccountId::from_str("r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ")?,
            fee: 12,
            sequence: XRPLSequence::Plain(1),
            amount: XRPLPaymentAmount::Issued(
                XRPLToken {
                    currency: "JPY".to_string().try_into()?,
                    issuer: XRPLAccountId::from_str("rrrrrrrrrrrrrrrrrrrrBZbvji")?,
                },
                XRPLTokenAmount::new(3369568318000000u64, -16),
            ),
            destination: XRPLAccountId::from_str("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh")?,
            cross_currency: Some(XRPLCrossCurrencyOptions{
                send_max: XRPLPaymentAmount::Issued(
                    XRPLToken {
                        currency: "USD".to_string().try_into()?,
                        issuer: XRPLAccountId::from_str("rw2521mDNXyKzHBrFGZ5Rj4wzUjS9FbiZq")?,
                    },
                    XRPLTokenAmount::new(8765432100000000u64, -16),
                ),
                paths: None
            })
        };
        let encoded_unsigned_tx = XRPLUnsignedTx::Payment(unsigned_tx).xrpl_serialize()?;
        assert_hex_eq!(
            "1200002200000000240000000161D44BF89AC2A40B800000000000000000000000004A50590000000000000000000000000000000000000000000000000168400000000000000C69D45F241D329F910000000000000000000000000055534400000000006919924835FA51D3991CDF5CF4505781227686E6730081145B812C9D57731E27A2DA8B1830195F88EF32A3B68314B5F762798A53D543A014CAF8B297CFF8F2F937E8",
            encoded_unsigned_tx
        );
        Ok(())
    }

    #[test]
    fn serialize_paths_transaction() -> Result<(), ContractError> {
        let unsigned_tx = XRPLPaymentTx {
            account: XRPLAccountId::from_str("r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ")?,
            fee: 12,
            sequence: XRPLSequence::Plain(1),
            amount: XRPLPaymentAmount::Issued(
                XRPLToken {
                    currency: "JPY".to_string().try_into()?,
                    issuer: XRPLAccountId::from_str("rrrrrrrrrrrrrrrrrrrrBZbvji")?,
                },
                XRPLTokenAmount::new(3369568318000000u64, -16),
            ),
            destination: XRPLAccountId::from_str("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh")?,
            cross_currency: Some(XRPLCrossCurrencyOptions{
                send_max: XRPLPaymentAmount::Issued(
                    XRPLToken {
                        currency: "USD".to_string().try_into()?,
                        issuer: XRPLAccountId::from_str("rw2521mDNXyKzHBrFGZ5Rj4wzUjS9FbiZq")?,
                    },
                    XRPLTokenAmount::new(8765432100000000u64, -16),
                ),
                paths: Some(XRPLPathSet {
                    paths: vec![
                        XRPLPath {
                            steps: vec![
                                XRPLPathStep::XRP,
                                XRPLPathStep::Account(
                                    XRPLAccountId::from_str("rrrrrrrrrrrrrrrrrrrrBZbvji")?,
                                )
                            ]
                        },
                        XRPLPath {
                            steps: vec![
                                XRPLPathStep::Currency(
                                    "EUR".to_string().try_into()?
                                ),
                                XRPLPathStep::Token(
                                    XRPLToken {
                                        issuer: XRPLAccountId::from_str("rrrrrrrrrrrrrrrrrrrrBZbvji")?,
                                        currency: "USD".to_string().try_into()?,
                                    }
                                ),
                            ]
                        }
                    ]
                })
            })
        };
        let encoded_unsigned_tx = XRPLUnsignedTx::Payment(unsigned_tx).xrpl_serialize()?;
        assert_hex_eq!(
            "1200002200000000240000000161D44BF89AC2A40B800000000000000000000000004A50590000000000000000000000000000000000000000000000000168400000000000000C69D45F241D329F910000000000000000000000000055534400000000006919924835FA51D3991CDF5CF4505781227686E6730081145B812C9D57731E27A2DA8B1830195F88EF32A3B68314B5F762798A53D543A014CAF8B297CFF8F2F937E80112100000000000000000000000000000000000000000010000000000000000000000000000000000000001FF100000000000000000000000004555520000000000300000000000000000000000005553440000000000000000000000000000000000000000000000000100",
            encoded_unsigned_tx
        );
        Ok(())
    }

    #[test]
    fn serialize_xrpl_unsigned_xrp_payment_transaction() -> Result<(), ContractError> {
        let tx = XRPLPaymentTx {
            account: XRPLAccountId::from_str("r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ")?,
            fee: 10,
            sequence: XRPLSequence::Plain(1),
            amount: XRPLPaymentAmount::Drops(1000),
            destination: XRPLAccountId::from_str("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh")?,
            cross_currency: None
        };
        let encoded_unsigned_tx = &XRPLUnsignedTx::Payment(tx).xrpl_serialize()?;
        assert_hex_eq!(
            "120000220000000024000000016140000000000003E868400000000000000A730081145B812C9D57731E27A2DA8B1830195F88EF32A3B68314B5F762798A53D543A014CAF8B297CFF8F2F937E8",
            encoded_unsigned_tx
        );

        let tx = XRPLPaymentTx {
            account: XRPLAccountId::from_str("rhKnz85JUKcrAizwxNUDfqCvaUi9ZMhuwj")?,
            fee: 3,
            sequence: XRPLSequence::Plain(43497363),
            amount: XRPLPaymentAmount::Drops(1000000000),
            destination: XRPLAccountId::from_str("rw2521mDNXyKzHBrFGZ5Rj4wzUjS9FbiZq")?,
            cross_currency: None
        };
        let encoded_unsigned_tx = &XRPLUnsignedTx::Payment(tx).xrpl_serialize()?;
        assert_hex_eq!(
            "1200002200000000240297B79361400000003B9ACA0068400000000000000373008114245409103F1B06F22FBCED389AAE0EFCE2F6689A83146919924835FA51D3991CDF5CF4505781227686E6",
            encoded_unsigned_tx
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
                account: XRPLAccountId::from_str("rfEf91bLxrTVC76vw1W3Ur8Jk4Lwujskmb")?,
                fee: 30,
                sequence: XRPLSequence::Ticket(44218193),
                amount: XRPLPaymentAmount::Drops(100000000),
                destination: XRPLAccountId::from_str("rfgqgX62inhKsfti1NR6FeMS8NcQJCFniG")?,
                cross_currency: None,
            }), signers: vec![
                XRPLSigner{
                    account: XRPLAccountId::from_str("r3mJFUQeVQma7qucT4iQSNCWuijVCPcicZ")?,
                    txn_signature: HexBinary::from_hex("3044022023DD4545108D411008FC9A76A58E1573AB0F8786413C8F38A92B1E2EAED60014022012A0A7890BFD0F0C8EA2C342107F65D4C91CAC29AAF3CF2840350BF3FB91E045")?,
                    signing_pub_key: pub_key_from_hex("025E0231BFAD810E5276E2CF9EB2F3F380CE0BDF6D84C3B6173499D3DDCC008856")?
                },
                XRPLSigner{
                    account: XRPLAccountId::from_str("rHxbKjRSFUUyuiio1jnFhimJRVAYYaGj7f")?,
                    txn_signature: HexBinary::from_hex("3045022100FC1490C236AD05A306EB5FD89072F14FEFC19ED35EB61BACD294D10E0910EDB102205A4CF0C0A759D7158A8FEE2F526C70277910DE88BF85564A1B3142AE635C9CE9")?,
                    signing_pub_key: pub_key_from_hex("036FF6F4B2BC5E08ABA924BD8FD986608F3685CA651A015B3D9D6A656DE14769FE")?
                }
            ],
        };
        let encoded_signed_tx = &signed_tx.xrpl_serialize()?;
        assert_hex_eq!(
            "12000022000000002400000000202902A2B751614000000005F5E10068400000000000001E73008114447BB6E37CA4D5D89FC2E2470A64632DA9BDD9E4831449599D50E0C1AC0CFC8D3B2A30830F3738EACC3EF3E0107321025E0231BFAD810E5276E2CF9EB2F3F380CE0BDF6D84C3B6173499D3DDCC00885674463044022023DD4545108D411008FC9A76A58E1573AB0F8786413C8F38A92B1E2EAED60014022012A0A7890BFD0F0C8EA2C342107F65D4C91CAC29AAF3CF2840350BF3FB91E0458114552A0D8EFCF978186CA9C37112B502D3728DA9EFE1E0107321036FF6F4B2BC5E08ABA924BD8FD986608F3685CA651A015B3D9D6A656DE14769FE74473045022100FC1490C236AD05A306EB5FD89072F14FEFC19ED35EB61BACD294D10E0910EDB102205A4CF0C0A759D7158A8FEE2F526C70277910DE88BF85564A1B3142AE635C9CE98114BA058AB3573EA34DC934D60E719A12DE6C213DE2E1F1",
            encoded_signed_tx
        );
        Ok(())
    }

    #[test]
    fn tx_serialization_sort_signers() -> Result<(), ContractError> {
        let signed_tx = XRPLSignedTransaction {
            unsigned_tx: XRPLUnsignedTx::Payment(XRPLPaymentTx {
                account: XRPLAccountId::from_str("rfEf91bLxrTVC76vw1W3Ur8Jk4Lwujskmb")?,
                fee: 30,
                sequence: XRPLSequence::Ticket(44218193),
                amount: XRPLPaymentAmount::Drops(100000000),
                destination: XRPLAccountId::from_str("rfgqgX62inhKsfti1NR6FeMS8NcQJCFniG")?,
                cross_currency: None
            }), signers: vec![
                XRPLSigner{
                    account: XRPLAccountId::from_str("rHxbKjRSFUUyuiio1jnFhimJRVAYYaGj7f")?,
                    txn_signature: HexBinary::from_hex("3045022100FC1490C236AD05A306EB5FD89072F14FEFC19ED35EB61BACD294D10E0910EDB102205A4CF0C0A759D7158A8FEE2F526C70277910DE88BF85564A1B3142AE635C9CE9")?,
                    signing_pub_key: pub_key_from_hex("036FF6F4B2BC5E08ABA924BD8FD986608F3685CA651A015B3D9D6A656DE14769FE")?
                },
                XRPLSigner{
                    account: XRPLAccountId::from_str("r3mJFUQeVQma7qucT4iQSNCWuijVCPcicZ")?,
                    txn_signature: HexBinary::from_hex("3044022023DD4545108D411008FC9A76A58E1573AB0F8786413C8F38A92B1E2EAED60014022012A0A7890BFD0F0C8EA2C342107F65D4C91CAC29AAF3CF2840350BF3FB91E045")?,
                    signing_pub_key: pub_key_from_hex("025E0231BFAD810E5276E2CF9EB2F3F380CE0BDF6D84C3B6173499D3DDCC008856")?
                },
            ],
        };
        let encoded_signed_tx = &signed_tx.xrpl_serialize()?;
        assert_hex_eq!(
            "12000022000000002400000000202902A2B751614000000005F5E10068400000000000001E73008114447BB6E37CA4D5D89FC2E2470A64632DA9BDD9E4831449599D50E0C1AC0CFC8D3B2A30830F3738EACC3EF3E0107321025E0231BFAD810E5276E2CF9EB2F3F380CE0BDF6D84C3B6173499D3DDCC00885674463044022023DD4545108D411008FC9A76A58E1573AB0F8786413C8F38A92B1E2EAED60014022012A0A7890BFD0F0C8EA2C342107F65D4C91CAC29AAF3CF2840350BF3FB91E0458114552A0D8EFCF978186CA9C37112B502D3728DA9EFE1E0107321036FF6F4B2BC5E08ABA924BD8FD986608F3685CA651A015B3D9D6A656DE14769FE74473045022100FC1490C236AD05A306EB5FD89072F14FEFC19ED35EB61BACD294D10E0910EDB102205A4CF0C0A759D7158A8FEE2F526C70277910DE88BF85564A1B3142AE635C9CE98114BA058AB3573EA34DC934D60E719A12DE6C213DE2E1F1",
            encoded_signed_tx
        );
        Ok(())
    }

    #[test]
    fn tx_serialization_ed25519_signers() -> Result<(), ContractError> {
        let signed_tx = XRPLSignedTransaction {
            unsigned_tx: XRPLUnsignedTx::Payment(XRPLPaymentTx {
                account: XRPLAccountId::from_str("r4ZMbbb4Y3KoeexmjEeTdhqUBrYjjWdyGM")?,
                fee: 30,
                sequence: XRPLSequence::Ticket(45205896),
                amount: XRPLPaymentAmount::Issued(XRPLToken{
                    currency: "ETH".to_string().try_into()?,
                    issuer: XRPLAccountId::from_str("r4ZMbbb4Y3KoeexmjEeTdhqUBrYjjWdyGM")?
                }, canonicalize_coin_amount(Uint128::from(100000000u128), 0)?),
                destination: XRPLAccountId::from_str("raNVNWvhUQzFkDDTdEw3roXRJfMJFVJuQo")?,
                cross_currency: None
            }), signers: vec![
                XRPLSigner{
                    account: XRPLAccountId::from_str("rBTmbPMAWghUv52pCCtkLYh5SPVy2PuDSj")?,
                    txn_signature: HexBinary::from_hex("531B9E854C81AEFA573C00DF1603C3DE80C1F3680D39A80F3FB725A0388D177E3EC5E28AD6760D9EEF8203FEB1FC61F9D9451F777114B97943E5702B54589E09")?,
                    signing_pub_key: PublicKey::Ed25519(HexBinary::from_hex("45e67eaf446e6c26eb3a2b55b64339ecf3a4d1d03180bee20eb5afdd23fa644f")?)
                },
                XRPLSigner{
                    account: XRPLAccountId::from_str("rhAdaMDgF89314TfNRHc5GsA6LQZdk35S5")?,
                    txn_signature: HexBinary::from_hex("76CF2097D7038B90445CB952AE52CBDBE6D55FE7C0562493FE3D9AAE5E05A66A43777CBCDAA89233CAFD4D1D0F9B02DB0619B9BB14957CC3ADAA8D7D343E0106")?,
                    signing_pub_key: PublicKey::Ed25519(HexBinary::from_hex("dd9822c7fa239dda9913ebee813ecbe69e35d88ff651548d5cc42c033a8a667b")?)
                },
            ],
        };
        let encoded_signed_tx = &signed_tx.xrpl_serialize()?;
        assert_hex_eq!(
            "12000022000000002400000000202902B1C98861D6838D7EA4C680000000000000000000000000004554480000000000EC792533BC26024CFAA5DDC2D04128E59581309C68400000000000001E73008114EC792533BC26024CFAA5DDC2D04128E59581309C831439659AAAD4DC8603798352FCF954419A67977536F3E0107321EDDD9822C7FA239DDA9913EBEE813ECBE69E35D88FF651548D5CC42C033A8A667B744076CF2097D7038B90445CB952AE52CBDBE6D55FE7C0562493FE3D9AAE5E05A66A43777CBCDAA89233CAFD4D1D0F9B02DB0619B9BB14957CC3ADAA8D7D343E010681142B3CF7B1986F5CB4EFEF11F933F40EC3106412C2E1E0107321ED45E67EAF446E6C26EB3A2B55B64339ECF3A4D1D03180BEE20EB5AFDD23FA644F7440531B9E854C81AEFA573C00DF1603C3DE80C1F3680D39A80F3FB725A0388D177E3EC5E28AD6760D9EEF8203FEB1FC61F9D9451F777114B97943E5702B54589E09811472C14C0DB6CEF64A87CC3D152D7B0E917D372BE7E1F1",
            encoded_signed_tx
        );
        Ok(())
    }

    #[test]
    fn serialize_xrpl_signed_xrp_ticket_create_transaction() -> Result<(), ContractError> {
        let signed_tx = XRPLSignedTransaction {
            unsigned_tx: XRPLUnsignedTx::TicketCreate(XRPLTicketCreateTx {
                account: XRPLAccountId::from_str("rfEf91bLxrTVC76vw1W3Ur8Jk4Lwujskmb")?,
                fee: 30,
                sequence: XRPLSequence::Plain(44218194),
                ticket_count: 3,
            }), signers: vec![
                XRPLSigner{
                    account: XRPLAccountId::from_str("r3mJFUQeVQma7qucT4iQSNCWuijVCPcicZ")?,
                    txn_signature: HexBinary::from_hex("304402203C10D5295AE4A34FD702355B075E951CF9FFE3A73F8B7557FB68E5DF64D87D3702200945D65BAAD7F10A14EA57E08914005F412709D10F27D868D63BE3052F30363F")?,
                    signing_pub_key: pub_key_from_hex("025E0231BFAD810E5276E2CF9EB2F3F380CE0BDF6D84C3B6173499D3DDCC008856")?
                },
                XRPLSigner{
                    account: XRPLAccountId::from_str("rHxbKjRSFUUyuiio1jnFhimJRVAYYaGj7f")?,
                    txn_signature: HexBinary::from_hex("3045022100EF2CBAC3B2D81E1E3502B064BA198D9D0D3F1FFE6604DAC5019C53C262B5F9E7022000808A438BD5CA808649DCDA6766D2BA0E8FA7E94150675F73FC41B2F73C9C58")?,
                    signing_pub_key: pub_key_from_hex("036FF6F4B2BC5E08ABA924BD8FD986608F3685CA651A015B3D9D6A656DE14769FE")?
                },
            ]
        };
        let encoded_signed_tx = signed_tx.xrpl_serialize()?;
        assert_hex_eq!(
            "12000A22000000002402A2B75220280000000368400000000000001E73008114447BB6E37CA4D5D89FC2E2470A64632DA9BDD9E4F3E0107321025E0231BFAD810E5276E2CF9EB2F3F380CE0BDF6D84C3B6173499D3DDCC0088567446304402203C10D5295AE4A34FD702355B075E951CF9FFE3A73F8B7557FB68E5DF64D87D3702200945D65BAAD7F10A14EA57E08914005F412709D10F27D868D63BE3052F30363F8114552A0D8EFCF978186CA9C37112B502D3728DA9EFE1E0107321036FF6F4B2BC5E08ABA924BD8FD986608F3685CA651A015B3D9D6A656DE14769FE74473045022100EF2CBAC3B2D81E1E3502B064BA198D9D0D3F1FFE6604DAC5019C53C262B5F9E7022000808A438BD5CA808649DCDA6766D2BA0E8FA7E94150675F73FC41B2F73C9C588114BA058AB3573EA34DC934D60E719A12DE6C213DE2E1F1",
            encoded_signed_tx
        );
        Ok(())
    }

    #[test]
    fn serialize_xrpl_signed_signer_list_set_transaction() -> Result<(), ContractError> {
        let signed_tx = XRPLSignedTransaction {
            unsigned_tx: XRPLUnsignedTx::SignerListSet(XRPLSignerListSetTx {
                account: XRPLAccountId::from_str("rfEf91bLxrTVC76vw1W3Ur8Jk4Lwujskmb")?,
                fee: 30,
                sequence: XRPLSequence::Plain(44218445),
                signer_quorum: 3,
                signer_entries: vec![
                    XRPLSignerEntry{
                        account: XRPLAccountId::from_str("r3mJFUQeVQma7qucT4iQSNCWuijVCPcicZ")?,
                        signer_weight: 2
                    },
                    XRPLSignerEntry{
                        account: XRPLAccountId::from_str("rHxbKjRSFUUyuiio1jnFhimJRVAYYaGj7f")?,
                        signer_weight: 1
                    }
                ],
            }), signers: vec![
                XRPLSigner{
                    account: XRPLAccountId::from_str("r3mJFUQeVQma7qucT4iQSNCWuijVCPcicZ")?,
                    txn_signature: HexBinary::from_hex("3045022100B94B346A418BE9EF5AEE7806EE984E3E9B48EB4ED48E79B5BFB69C607167023E02206B14BD72B69206D14DADA82ACCDD2539D275719FB187ECE2A46BAC9025877B39")?,
                    signing_pub_key: pub_key_from_hex("025E0231BFAD810E5276E2CF9EB2F3F380CE0BDF6D84C3B6173499D3DDCC008856")?,
                },
                XRPLSigner{
                    account: XRPLAccountId::from_str("rHxbKjRSFUUyuiio1jnFhimJRVAYYaGj7f")?,
                    txn_signature: HexBinary::from_hex("3044022072A1028FF972D9D6E950810AF72443EEE352ADB1BC54B1112983842C857C464502206D74A77387979A47863F08F9191611D142C2BD6B32D5C750EF58513C5669F21A")?,
                    signing_pub_key: pub_key_from_hex("036FF6F4B2BC5E08ABA924BD8FD986608F3685CA651A015B3D9D6A656DE14769FE")?,
                },
            ],
        };
        let encoded_signed_tx = signed_tx.xrpl_serialize()?;
        assert_hex_eq!(
            "12000C22000000002402A2B84D20230000000368400000000000001E73008114447BB6E37CA4D5D89FC2E2470A64632DA9BDD9E4F3E0107321025E0231BFAD810E5276E2CF9EB2F3F380CE0BDF6D84C3B6173499D3DDCC00885674473045022100B94B346A418BE9EF5AEE7806EE984E3E9B48EB4ED48E79B5BFB69C607167023E02206B14BD72B69206D14DADA82ACCDD2539D275719FB187ECE2A46BAC9025877B398114552A0D8EFCF978186CA9C37112B502D3728DA9EFE1E0107321036FF6F4B2BC5E08ABA924BD8FD986608F3685CA651A015B3D9D6A656DE14769FE74463044022072A1028FF972D9D6E950810AF72443EEE352ADB1BC54B1112983842C857C464502206D74A77387979A47863F08F9191611D142C2BD6B32D5C750EF58513C5669F21A8114BA058AB3573EA34DC934D60E719A12DE6C213DE2E1F1F4EB1300028114552A0D8EFCF978186CA9C37112B502D3728DA9EFE1EB1300018114BA058AB3573EA34DC934D60E719A12DE6C213DE2E1F1",
            encoded_signed_tx
        );
        Ok(())
    }
}
