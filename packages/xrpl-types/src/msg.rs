use axelar_wasm_std::msg_id::HexTxHash;
use axelar_wasm_std::nonempty;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Attribute, HexBinary};
use router_api::{ChainName, ChainNameRaw, CrossChainId, FIELD_DELIMITER};
use sha3::{Digest, Keccak256};

use crate::types::{xrpl_account_id_string, XRPLAccountId, XRPLPaymentAmount};
use crate::{hex_option, hex_tx_hash};

#[cw_serde]
#[derive(Eq, Hash)]
pub struct WithCrossChainId<T> {
    #[serde(flatten)]
    pub content: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc_id: Option<CrossChainId>,
}

impl<T> WithCrossChainId<T> {
    pub fn new(content: T, cc_id: Option<CrossChainId>) -> Self {
        Self { content, cc_id }
    }
}

#[cw_serde]
#[derive(Eq, Hash)]
pub enum XRPLMessage {
    ProverMessage(XRPLProverMessage),
    InterchainTransferMessage(XRPLInterchainTransferMessage),
    CallContractMessage(XRPLCallContractMessage),
    AddGasMessage(XRPLAddGasMessage),
    AddReservesMessage(XRPLAddReservesMessage),
}

#[cw_serde]
#[derive(Eq, Hash)]
pub enum XRPLMessageType {
    Proof,
    InterchainTransfer,
    CallContract,
    AddGas,
    AddReserves,
}

impl std::fmt::Display for XRPLMessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            XRPLMessageType::Proof => "proof",
            XRPLMessageType::InterchainTransfer => "interchain_transfer",
            XRPLMessageType::CallContract => "call_contract",
            XRPLMessageType::AddGas => "add_gas",
            XRPLMessageType::AddReserves => "add_reserves",
        };
        write!(f, "{}", s)
    }
}

impl XRPLMessage {
    pub fn tx_id(&self) -> HexTxHash {
        match self {
            XRPLMessage::ProverMessage(prover_message) => prover_message.tx_id.clone(),
            XRPLMessage::InterchainTransferMessage(interchain_transfer_message) => {
                interchain_transfer_message.tx_id.clone()
            }
            XRPLMessage::CallContractMessage(call_contract_message) => {
                call_contract_message.tx_id.clone()
            }
            XRPLMessage::AddGasMessage(add_gas_message) => add_gas_message.tx_id.clone(),
            XRPLMessage::AddReservesMessage(add_reserves_message) => {
                add_reserves_message.tx_id.clone()
            }
        }
    }

    pub fn cc_id(&self, source_chain: ChainNameRaw) -> Option<CrossChainId> {
        match self {
            XRPLMessage::InterchainTransferMessage(interchain_transfer_message) => {
                Some(interchain_transfer_message.cc_id(source_chain))
            }
            XRPLMessage::CallContractMessage(call_contract_message) => {
                Some(call_contract_message.cc_id(source_chain))
            }
            XRPLMessage::ProverMessage(_) => None,
            XRPLMessage::AddGasMessage(_) => None,
            XRPLMessage::AddReservesMessage(_) => None,
        }
    }

    pub fn with_cc_id(&self, source_chain: ChainNameRaw) -> WithCrossChainId<Self> {
        WithCrossChainId::new(self.clone(), self.cc_id(source_chain))
    }

    pub fn hash(&self) -> [u8; 32] {
        match self {
            XRPLMessage::ProverMessage(prover_message) => prover_message.hash(),
            XRPLMessage::InterchainTransferMessage(interchain_transfer_message) => {
                interchain_transfer_message.hash()
            }
            XRPLMessage::CallContractMessage(call_contract_message) => call_contract_message.hash(),
            XRPLMessage::AddGasMessage(add_gas_message) => add_gas_message.hash(),
            XRPLMessage::AddReservesMessage(add_reserves_message) => add_reserves_message.hash(),
        }
    }
}

/// Represents an XRPL `Payment` transaction towards the XRPL multisig,
/// performed by an XRPL user to initiate an interchain transfer call.
/// Such messages are verified by the XRPL Voting Verifier and routed by the Router.
#[cw_serde]
#[derive(Eq, Hash)]
pub struct XRPLInterchainTransferMessage {
    #[serde(with = "hex_tx_hash")]
    #[schemars(with = "String")] // necessary attribute in conjunction with #[serde(with ...)]
    pub tx_id: HexTxHash,
    #[serde(with = "xrpl_account_id_string")]
    #[schemars(with = "String")]
    pub source_address: XRPLAccountId,
    pub destination_chain: ChainName,
    pub destination_address: nonempty::String,
    /// for better user experience, the payload hash gets encoded into hex at the edges (input/output),
    /// but internally, we treat it as raw bytes to enforce its format.
    #[serde(with = "hex_option")]
    #[schemars(with = "String")]
    pub payload_hash: Option<[u8; 32]>,
    /// The total amount of tokens sent to the XRPL multisig,
    /// including the gas fee.
    pub transfer_amount: XRPLPaymentAmount,
    pub gas_fee_amount: XRPLPaymentAmount,
}

/// Represents an XRPL `Payment` transaction towards the XRPL multisig,
/// performed by an XRPL user to initiate a contract call.
/// Such messages are verified by the XRPL Voting Verifier and routed by the Router.
#[cw_serde]
#[derive(Eq, Hash)]
pub struct XRPLCallContractMessage {
    #[serde(with = "hex_tx_hash")]
    #[schemars(with = "String")] // necessary attribute in conjunction with #[serde(with ...)]
    pub tx_id: HexTxHash,
    #[serde(with = "xrpl_account_id_string")]
    #[schemars(with = "String")]
    pub source_address: XRPLAccountId,
    pub destination_chain: ChainName,
    pub destination_address: nonempty::String,
    /// for better user experience, the payload hash gets encoded into hex at the edges (input/output),
    /// but internally, we treat it as raw bytes to enforce its format.
    #[serde(with = "axelar_wasm_std::hex")]
    #[schemars(with = "String")]
    pub payload_hash: [u8; 32],
    /// Should be exactly equal to the deposited amount.
    pub gas_fee_amount: XRPLPaymentAmount,
}

/// Represents an XRPL multisig transaction generated by the XRPL Multisig Prover,
/// signed by Axelar verifiers and broadcasted to XRPL. These could be
/// `Payment`, `SignerListSet`, `TicketCreate`, or `TrustSet` XRPL transactions.
/// Such messages are verified by the XRPL Voting Verifier and confirmed by the XRPL Multisig Prover.
#[cw_serde]
#[derive(Eq, Hash)]
pub struct XRPLProverMessage {
    #[serde(with = "hex_tx_hash")]
    #[schemars(with = "String")]
    pub tx_id: HexTxHash,

    /// The hash of the unsigned XRPL transaction. This is used to confirm
    /// the transaction's status, while ignoring the signatures.
    #[serde(with = "hex_tx_hash")]
    #[schemars(with = "String")]
    pub unsigned_tx_hash: HexTxHash,
}

/// Represents an XRPL `Payment` transaction towards the XRPL multisig,
/// performed by an XRPL user who wishes to top-up the gas paid
/// for an existing interchain transfer and/or GMP call (see `XRPLInterchainTransferMessage`).
/// Such messages are verified by the XRPL Voting Verifier and confirmed on the XRPL Gateway.
#[cw_serde]
#[derive(Eq, Hash)]
pub struct XRPLAddGasMessage {
    #[serde(with = "hex_tx_hash")]
    #[schemars(with = "String")]
    pub tx_id: HexTxHash,
    /// The transaction hash of the original user message
    /// that this gas top-up is for.
    #[serde(with = "hex_tx_hash")]
    #[schemars(with = "String")]
    pub msg_id: HexTxHash,
    pub amount: XRPLPaymentAmount,
    #[serde(with = "xrpl_account_id_string")]
    #[schemars(with = "String")]
    pub source_address: XRPLAccountId,
}

/// Represents an XRPL `Payment` transaction towards the XRPL multisig,
/// performed by the relayer to top-up the fee reserve
/// that is used to pay for prover transaction fees
/// (i.e., TXs generated by the XRPL Multisig Prover).
/// Reserves are used to keep the XRPL multisig account active
/// (https://xrpl.org/docs/concepts/accounts/reserves)
/// and to pay for the transaction fees of the multisig account.
/// Such messages are verified by the XRPL Voting Verifier and confirmed on the XRPL Multisig Prover.
#[cw_serde]
#[derive(Eq, Hash)]
pub struct XRPLAddReservesMessage {
    #[serde(with = "hex_tx_hash")]
    #[schemars(with = "String")]
    pub tx_id: HexTxHash,
    pub amount: u64,
}

impl From<XRPLInterchainTransferMessage> for Vec<Attribute> {
    fn from(other: XRPLInterchainTransferMessage) -> Self {
        let mut array = vec![
            ("tx_id", other.tx_id.tx_hash_as_hex_no_prefix()).into(),
            ("source_address", other.source_address.to_string()).into(),
            ("destination_chain", other.destination_chain).into(),
            ("destination_address", other.destination_address.to_string()).into(),
            ("transfer_amount", other.transfer_amount.to_string()).into(),
            ("gas_fee_amount", other.gas_fee_amount.to_string()).into(),
        ];

        if let Some(hash) = other.payload_hash {
            array.push(("payload_hash", HexBinary::from(hash).to_string()).into())
        }

        array
    }
}

impl From<XRPLCallContractMessage> for Vec<Attribute> {
    fn from(other: XRPLCallContractMessage) -> Self {
        vec![
            ("tx_id", other.tx_id.tx_hash_as_hex_no_prefix()).into(),
            ("source_address", other.source_address.to_string()).into(),
            ("destination_chain", other.destination_chain).into(),
            ("destination_address", other.destination_address.to_string()).into(),
            (
                "payload_hash",
                HexBinary::from(other.payload_hash).to_string(),
            )
                .into(),
            ("gas_fee_amount", other.gas_fee_amount.to_string()).into(),
        ]
    }
}

impl From<XRPLProverMessage> for Vec<Attribute> {
    fn from(other: XRPLProverMessage) -> Self {
        vec![
            ("tx_id", other.tx_id.tx_hash_as_hex_no_prefix()).into(),
            (
                "unsigned_tx_hash",
                other.unsigned_tx_hash.tx_hash_as_hex_no_prefix(),
            )
                .into(),
        ]
    }
}

impl From<XRPLAddGasMessage> for Vec<Attribute> {
    fn from(other: XRPLAddGasMessage) -> Self {
        vec![
            ("tx_id", other.tx_id.tx_hash_as_hex_no_prefix()).into(),
            ("msg_id", other.msg_id.tx_hash_as_hex_no_prefix()).into(),
            ("amount", other.amount.to_string()).into(),
            ("source_address", other.source_address.to_string()).into(),
        ]
    }
}

impl From<XRPLAddReservesMessage> for Vec<Attribute> {
    fn from(other: XRPLAddReservesMessage) -> Self {
        vec![
            ("tx_id", other.tx_id.tx_hash_as_hex_no_prefix()).into(),
            ("amount", other.amount.to_string()).into(),
        ]
    }
}

impl From<XRPLMessage> for Vec<Attribute> {
    fn from(other: XRPLMessage) -> Self {
        let (mut attrs, msg_type): (Self, &str) = match other {
            XRPLMessage::InterchainTransferMessage(msg) => {
                (msg.into(), "interchain_transfer_message")
            }
            XRPLMessage::CallContractMessage(msg) => (msg.into(), "call_contract_message"),
            XRPLMessage::ProverMessage(msg) => (msg.into(), "prover_message"),
            XRPLMessage::AddGasMessage(msg) => (msg.into(), "add_gas_message"),
            XRPLMessage::AddReservesMessage(msg) => (msg.into(), "add_reserves_message"),
        };
        attrs.push(("type", msg_type).into());
        attrs
    }
}

impl XRPLProverMessage {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        let delimiter_bytes = &[FIELD_DELIMITER as u8];

        hasher.update(self.tx_id.tx_hash.as_ref());
        hasher.update(delimiter_bytes);
        hasher.update(self.unsigned_tx_hash.tx_hash.as_ref());

        hasher.finalize().into()
    }
}

impl XRPLInterchainTransferMessage {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        let delimiter_bytes = &[FIELD_DELIMITER as u8];

        hasher.update(self.tx_id.tx_hash.as_ref());
        hasher.update(delimiter_bytes);
        hasher.update(self.source_address.as_ref());
        hasher.update(delimiter_bytes);
        hasher.update(self.destination_chain.as_ref());
        hasher.update(delimiter_bytes);
        hasher.update(self.destination_address.as_str());
        hasher.update(delimiter_bytes);
        hasher.update(self.transfer_amount.hash());

        if let Some(hash) = self.payload_hash {
            hasher.update(delimiter_bytes);
            hasher.update(hash);
        }

        hasher.finalize().into()
    }

    pub fn cc_id(&self, source_chain: ChainNameRaw) -> CrossChainId {
        CrossChainId {
            source_chain,
            message_id: self.tx_id.tx_hash_as_hex(),
        }
    }
}

impl XRPLCallContractMessage {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        let delimiter_bytes = &[FIELD_DELIMITER as u8];

        hasher.update(self.tx_id.tx_hash.as_ref());
        hasher.update(delimiter_bytes);
        hasher.update(self.source_address.as_ref());
        hasher.update(delimiter_bytes);
        hasher.update(self.destination_chain.as_ref());
        hasher.update(delimiter_bytes);
        hasher.update(self.destination_address.as_str());
        hasher.update(delimiter_bytes);
        hasher.update(self.payload_hash);
        hasher.update(delimiter_bytes);
        hasher.update(self.gas_fee_amount.hash());

        hasher.finalize().into()
    }

    pub fn cc_id(&self, source_chain: ChainNameRaw) -> CrossChainId {
        CrossChainId {
            source_chain,
            message_id: format!("0x{}", HexBinary::from(self.tx_id.tx_hash).to_hex())
                .try_into()
                .expect("message_id conversion should never fail"),
        }
    }
}

impl XRPLAddGasMessage {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        let delimiter_bytes = &[FIELD_DELIMITER as u8];

        hasher.update(self.tx_id.tx_hash.as_ref());
        hasher.update(delimiter_bytes);
        hasher.update(self.msg_id.tx_hash.as_ref());
        hasher.update(delimiter_bytes);
        hasher.update(self.amount.hash());
        hasher.update(delimiter_bytes);
        hasher.update(self.source_address.as_ref());

        hasher.finalize().into()
    }
}

impl From<XRPLAddGasMessage> for XRPLMessage {
    fn from(val: XRPLAddGasMessage) -> Self {
        XRPLMessage::AddGasMessage(val)
    }
}

impl XRPLAddReservesMessage {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        let delimiter_bytes = &[FIELD_DELIMITER as u8];

        hasher.update(self.tx_id.tx_hash.as_ref());
        hasher.update(delimiter_bytes);
        hasher.update(self.amount.to_be_bytes());

        hasher.finalize().into()
    }
}

impl From<XRPLInterchainTransferMessage> for XRPLMessage {
    fn from(val: XRPLInterchainTransferMessage) -> Self {
        XRPLMessage::InterchainTransferMessage(val)
    }
}

#[cw_serde]
#[derive(Eq, Hash)]
pub struct WithPayload<T: Clone + Into<XRPLMessage>> {
    pub message: T,
    pub payload: Option<nonempty::HexBinary>,
}

impl WithPayload<XRPLMessage> {
    pub fn new(message: XRPLMessage, payload: Option<nonempty::HexBinary>) -> Self {
        Self { message, payload }
    }
}

impl<T: Clone + Into<XRPLMessage>> From<WithPayload<T>> for XRPLMessage {
    fn from(val: WithPayload<T>) -> Self {
        val.message.into()
    }
}
