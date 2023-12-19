use std::ops::Deref;

use connection_router::state::CrossChainId;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{from_binary, HexBinary, StdResult, Uint256};
use cw_storage_plus::{Key, KeyDeserialize, PrimaryKey};
use multisig::key::Signature;
use xrpl_voting_verifier::execute::MessageStatus;

use crate::{xrpl_multisig::XRPLUnsignedTx, error::ContractError};

#[cw_serde]
pub enum TransactionStatus {
    Pending,
    Succeeded,
    FailedOnChain,
    FailedOffChain,
}

#[cw_serde]
pub struct TxHash(pub HexBinary);

impl TryFrom<CrossChainId> for TxHash {
    type Error = ContractError;
    fn try_from(cc_id: CrossChainId) -> Result<Self, ContractError> {
        // TODO check this is correct
        Ok(Self(HexBinary::from_hex(cc_id.id.deref().as_str())?))
    }
}

impl Into<HexBinary> for TxHash {
    fn into(self) -> HexBinary {
        self.0
    }
}

impl Into<TransactionStatus> for MessageStatus {
    fn into(self) -> TransactionStatus {
        match self {
            MessageStatus::Succeeded => TransactionStatus::Succeeded,
            MessageStatus::FailedOnChain => TransactionStatus::FailedOnChain,
            MessageStatus::FailedOffChain => TransactionStatus::FailedOffChain,
        }
    }
}

#[cw_serde]
pub struct TransactionInfo {
    pub status: TransactionStatus,
    // TODO: save only the hash of the unsigned tx
    pub unsigned_contents: XRPLUnsignedTx,
    // TODO: rename: original_message_id or similar, the message id that triggered this tx
    pub message_id: Option<CrossChainId>,
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
        Ok(from_binary(&value.into()).expect("violated invariant: TxHash is not deserializable"))
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
    pub issuer: String,
    pub currency: String,
}

impl XRPLToken {
    pub const NATIVE_CURRENCY: &str = "XRP";
}
