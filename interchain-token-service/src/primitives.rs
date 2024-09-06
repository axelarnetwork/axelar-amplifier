use std::fmt::Display;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint256};
use router_api::ChainNameRaw;
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
    /// Transfer ITS tokens between different chains
    InterchainTransfer {
        /// The unique identifier of the token being transferred
        token_id: TokenId,
        /// The address that called the ITS contract on the source chain
        source_address: HexBinary,
        /// The address that the token will be sent to on the destination chain
        /// If data is not empty, this address will given the token and executed as a contract on the destination chain
        destination_address: HexBinary,
        /// The amount of tokens to transfer
        amount: Uint256,
        /// An optional payload to be provided to the destination address, if `data` is not empty
        data: HexBinary,
    },
    /// Deploy a new interchain token on the destination chain
    DeployInterchainToken {
        /// The unique identifier of the token to be deployed
        token_id: TokenId,
        /// The name of the token
        name: String,
        /// The symbol of the token
        symbol: String,
        /// The number of decimal places the token supports
        decimals: u8,
        /// The address that will be the initial minter of the token (in addition to the ITS contract)
        minter: HexBinary,
    },
    /// Deploy a new token manager on the destination chain
    DeployTokenManager {
        /// The unique identifier of the token that the token manager will manage
        token_id: TokenId,
        /// The type of token manager to deploy
        token_manager_type: TokenManagerType,
        /// The parameters to be provided to the token manager contract
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
        destination_chain: ChainNameRaw,
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
