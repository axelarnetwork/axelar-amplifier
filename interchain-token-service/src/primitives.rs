use std::fmt::Display;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint256};
use router_api::{ChainName, ChainNameRaw};
use strum::FromRepr;

/// A unique 32-byte identifier for linked cross-chain tokens across ITS contracts.
#[cw_serde]
#[derive(Eq)]
pub struct TokenId(
    #[serde(with = "axelar_wasm_std::hex")]
    #[schemars(with = "String")]
    [u8; 32],
);

impl Display for TokenId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// The supported types of token managers that can be deployed by ITS contracts.
#[cw_serde]
#[derive(Eq, Copy, FromRepr)]
#[repr(u8)]
pub enum TokenManagerType {
    NativeInterchainToken,
    MintBurnFrom,
    LockUnlock,
    LockUnlockFee,
    MintBurn,
    Gateway,
}

/// A message sent between ITS contracts to facilitate interchain transfers, token deployments, or token manager deployments.
/// `Message` routed via the ITS hub get wrapped inside a [`HubMessage`]
#[cw_serde]
#[derive(Eq, strum::IntoStaticStr)]
pub enum Message {
    InterchainTransfer {
        token_id: TokenId,
        source_address: HexBinary,
        destination_address: HexBinary,
        amount: Uint256,
        data: HexBinary,
    },
    DeployInterchainToken {
        token_id: TokenId,
        name: String,
        symbol: String,
        decimals: u8,
        minter: HexBinary,
    },
    DeployTokenManager {
        token_id: TokenId,
        token_manager_type: TokenManagerType,
        params: HexBinary,
    },
}

/// A message sent between ITS edge contracts and the ITS hub contract (defined in this crate).
/// `HubMessage` is used to route an ITS [`Message`] between ITS edge contracts on different chains via the ITS Hub.
#[cw_serde]
#[derive(Eq)]
pub enum HubMessage {
    /// ITS edge source contract -> ITS Hub
    SendToHub {
        /// True destination chain of the ITS message
        destination_chain: ChainName,
        message: Message,
    },
    /// ITS Hub -> ITS edge destination contract
    ReceiveFromHub {
        /// True source chain of the ITS message
        source_chain: ChainNameRaw,
        message: Message,
    },
}

impl HubMessage {
    pub fn message(&self) -> &Message {
        match self {
            HubMessage::SendToHub { message, .. } => message,
            HubMessage::ReceiveFromHub { message, .. } => message,
        }
    }
}

impl TokenId {
    #[inline(always)]
    pub fn new(id: [u8; 32]) -> Self {
        id.into()
    }
}

impl From<[u8; 32]> for TokenId {
    #[inline(always)]
    fn from(id: [u8; 32]) -> Self {
        Self(id)
    }
}

impl From<TokenId> for [u8; 32] {
    #[inline(always)]
    fn from(id: TokenId) -> Self {
        id.0
    }
}
