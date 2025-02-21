use axelar_wasm_std::nonempty;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Attribute, HexBinary};
use router_api::{ChainName, ChainNameRaw, CrossChainId, Message, FIELD_DELIMITER};
use sha3::{Digest, Keccak256};

use crate::hex_option;
use crate::types::{tx_hash_hex, xrpl_account_id_string, TxHash, XRPLAccountId, XRPLPaymentAmount};

#[cw_serde]
#[derive(Eq, Hash)]
pub enum XRPLMessage {
    ProverMessage(XRPLProverMessage),
    UserMessage(XRPLUserMessage),
}

impl XRPLMessage {
    pub fn tx_id(&self) -> TxHash {
        match self {
            XRPLMessage::ProverMessage(prover_message) => prover_message.tx_id.clone(),
            XRPLMessage::UserMessage(user_message) => user_message.tx_id.clone(),
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        match self {
            XRPLMessage::ProverMessage(prover_message) => prover_message.hash(),
            XRPLMessage::UserMessage(user_message) => user_message.hash(),
        }
    }
}

/// Represents a transaction originating from a user that is sent to the XRPL multisig.
#[cw_serde]
#[derive(Eq, Hash)]
pub struct XRPLUserMessage {
    #[serde(with = "tx_hash_hex")]
    #[schemars(with = "String")] // necessary attribute in conjunction with #[serde(with ...)]
    pub tx_id: TxHash,
    #[serde(with = "xrpl_account_id_string")]
    #[schemars(with = "String")]
    pub source_address: XRPLAccountId,
    pub destination_chain: ChainName,
    pub destination_address: nonempty::HexBinary,
    /// for better user experience, the payload hash gets encoded into hex at the edges (input/output),
    /// but internally, we treat it as raw bytes to enforce its format.
    #[serde(with = "hex_option")]
    #[schemars(with = "String")]
    pub payload_hash: Option<[u8; 32]>,
    pub amount: XRPLPaymentAmount,
}

/// Represents a transaction generated by the Multisig Prover that is posted on XRPL.
#[cw_serde]
#[derive(Eq, Hash)]
pub struct XRPLProverMessage {
    #[serde(with = "tx_hash_hex")]
    #[schemars(with = "String")]
    pub tx_id: TxHash,

    /// The hash of the unsigned XRPL transaction. This is used to verify
    /// the transaction that was posted, while ignoring the signatures.
    #[serde(with = "tx_hash_hex")]
    #[schemars(with = "String")]
    pub unsigned_tx_hash: TxHash,
}

impl From<XRPLUserMessage> for Vec<Attribute> {
    fn from(other: XRPLUserMessage) -> Self {
        let mut array = vec![
            ("tx_id", HexBinary::from(other.tx_id).to_string()).into(),
            ("source_address", other.source_address.to_string()).into(),
            ("destination_chain", other.destination_chain).into(),
            ("destination_address", other.destination_address.to_string()).into(),
            ("amount", other.amount.to_string()).into(),
        ];

        if let Some(hash) = other.payload_hash {
            array.push(("payload_hash", HexBinary::from(hash).to_string()).into())
        }

        array
    }
}

impl From<XRPLProverMessage> for Vec<Attribute> {
    fn from(other: XRPLProverMessage) -> Self {
        vec![
            ("tx_id", HexBinary::from(other.tx_id).to_string()).into(),
            (
                "unsigned_tx_hash",
                HexBinary::from(other.unsigned_tx_hash).to_string(),
            )
                .into(),
        ]
    }
}

impl From<XRPLMessage> for Vec<Attribute> {
    fn from(other: XRPLMessage) -> Self {
        let (mut attrs, msg_type): (Self, &str) = match other {
            XRPLMessage::ProverMessage(msg) => (msg.into(), "prover_message"),
            XRPLMessage::UserMessage(msg) => (msg.into(), "user_message"),
        };
        attrs.push(("type", msg_type).into());
        attrs
    }
}

impl XRPLProverMessage {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        let delimiter_bytes = &[FIELD_DELIMITER as u8];

        hasher.update(self.tx_id.as_ref());
        hasher.update(delimiter_bytes);
        hasher.update(self.unsigned_tx_hash.as_ref());

        hasher.finalize().into()
    }
}

impl XRPLUserMessage {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        let delimiter_bytes = &[FIELD_DELIMITER as u8];

        hasher.update(self.tx_id.as_ref());
        hasher.update(delimiter_bytes);
        hasher.update(self.source_address.as_ref());
        hasher.update(delimiter_bytes);
        hasher.update(self.destination_chain.as_ref());
        hasher.update(delimiter_bytes);
        hasher.update(self.destination_address.as_ref());
        hasher.update(delimiter_bytes);
        hasher.update(self.amount.hash());

        if let Some(hash) = self.payload_hash {
            hasher.update(delimiter_bytes);
            hasher.update(hash);
        }

        hasher.finalize().into()
    }
}

impl From<XRPLUserMessage> for XRPLMessage {
    fn from(val: XRPLUserMessage) -> Self {
        XRPLMessage::UserMessage(val)
    }
}

pub trait CrossChainMessage {
    fn cc_id(&self, source_chain: ChainNameRaw) -> CrossChainId;
}

impl CrossChainMessage for Message {
    fn cc_id(&self, _: ChainNameRaw) -> CrossChainId {
        self.cc_id.clone()
    }
}

impl CrossChainMessage for XRPLMessage {
    fn cc_id(&self, source_chain: ChainNameRaw) -> CrossChainId {
        match self {
            XRPLMessage::ProverMessage(prover_message) => prover_message.cc_id(source_chain),
            XRPLMessage::UserMessage(user_message) => user_message.cc_id(source_chain),
        }
    }
}

impl CrossChainMessage for TxHash {
    fn cc_id(&self, source_chain: ChainNameRaw) -> CrossChainId {
        CrossChainId {
            source_chain,
            message_id: format!("0x{}", HexBinary::from(self.clone()).to_hex())
                .try_into()
                .expect("message_id conversion should never fail"),
        }
    }
}

impl CrossChainMessage for XRPLProverMessage {
    fn cc_id(&self, source_chain: ChainNameRaw) -> CrossChainId {
        CrossChainId {
            source_chain,
            message_id: format!("0x{}", HexBinary::from(self.tx_id.clone()).to_hex())
                .try_into()
                .expect("message_id conversion should never fail"),
        }
    }
}

impl CrossChainMessage for XRPLUserMessage {
    fn cc_id(&self, source_chain: ChainNameRaw) -> CrossChainId {
        CrossChainId {
            source_chain,
            message_id: format!("0x{}", HexBinary::from(self.tx_id.clone()).to_hex())
                .try_into()
                .expect("message_id conversion should never fail"),
        }
    }
}
