use std::fmt::Display;

use axelar_wasm_std::nonempty;
use cosmwasm_schema::cw_serde;
use cw_storage_plus::{Key, KeyDeserialize, Prefixer, PrimaryKey};
use router_api::ChainNameRaw;
use strum::FromRepr;

/// A unique 32-byte identifier for linked cross-chain tokens across ITS contracts.
#[cw_serde]
#[derive(Eq, Hash, Copy)]
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
#[derive(Eq, Copy, FromRepr, strum::AsRefStr)]
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
#[derive(Eq, strum::AsRefStr)]
pub enum Message {
    /// Transfer ITS tokens between different chains
    InterchainTransfer(InterchainTransfer),
    /// Deploy a new interchain token on the destination chain
    DeployInterchainToken(DeployInterchainToken),
    /// Deploy a new token manager on the destination chain
    DeployTokenManager(DeployTokenManager),
}

#[cw_serde]
#[derive(Eq)]
pub struct InterchainTransfer {
    /// The unique identifier of the token being transferred
    pub token_id: TokenId,
    /// The address that called the ITS contract on the source chain
    pub source_address: nonempty::HexBinary,
    /// The address that the token will be sent to on the destination chain
    /// If data is not empty, this address will give the token and executed as a contract on the destination chain
    pub destination_address: nonempty::HexBinary,
    /// The amount of tokens to transfer
    pub amount: nonempty::Uint256,
    /// An optional payload to be provided to the destination address, if `data` is not empty
    pub data: Option<nonempty::HexBinary>,
}

impl From<InterchainTransfer> for Message {
    fn from(value: InterchainTransfer) -> Self {
        Message::InterchainTransfer(value)
    }
}

#[cw_serde]
#[derive(Eq)]
pub struct DeployInterchainToken {
    /// The unique identifier of the token to be deployed
    pub token_id: TokenId,
    /// The name of the token
    pub name: nonempty::String,
    /// The symbol of the token
    pub symbol: nonempty::String,
    /// The number of decimal places the token supports
    pub decimals: u8,
    /// An additional minter of the token (optional). ITS on the external chain is always a minter.
    pub minter: Option<nonempty::HexBinary>,
}

impl From<DeployInterchainToken> for Message {
    fn from(value: DeployInterchainToken) -> Self {
        Message::DeployInterchainToken(value)
    }
}

#[cw_serde]
#[derive(Eq)]
pub struct DeployTokenManager {
    /// The unique identifier of the token that the token manager will manage
    pub token_id: TokenId,
    /// The type of token manager to deploy
    pub token_manager_type: TokenManagerType,
    /// The parameters to be provided to the token manager contract
    pub params: nonempty::HexBinary,
}

impl From<DeployTokenManager> for Message {
    fn from(value: DeployTokenManager) -> Self {
        Message::DeployTokenManager(value)
    }
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

    pub fn token_id(&self) -> TokenId {
        self.message().token_id()
    }
}

impl Message {
    pub fn token_id(&self) -> TokenId {
        match self {
            Message::InterchainTransfer(InterchainTransfer { token_id, .. })
            | Message::DeployInterchainToken(DeployInterchainToken { token_id, .. })
            | Message::DeployTokenManager(DeployTokenManager { token_id, .. }) => *token_id,
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

impl<'a> PrimaryKey<'a> for TokenId {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        self.0.key()
    }
}

impl KeyDeserialize for TokenId {
    type Output = TokenId;
    fn from_vec(value: Vec<u8>) -> cosmwasm_std::StdResult<Self::Output> {
        let inner = <[u8; 32]>::from_vec(value)?;
        Ok(TokenId(inner))
    }
}

impl<'a> Prefixer<'a> for TokenId {
    fn prefix(&self) -> Vec<Key> {
        self.key()
    }
}
