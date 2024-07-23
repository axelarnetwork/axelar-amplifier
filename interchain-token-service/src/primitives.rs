use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint256};
use router_api::ChainName;
use strum::FromRepr;

#[cw_serde]
#[derive(Eq)]
pub struct TokenId(
    #[serde(with = "axelar_wasm_std::hex")]
    #[schemars(with = "String")]
    [u8; 32],
);

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

/// ITS message type that can be sent between ITS contracts for transfers/token deployments
/// `ItsMessage` that are routed via the ITS hub get wrapped inside `ItsHubMessage`
#[cw_serde]
#[derive(Eq)]
pub enum ItsMessage {
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

/// ITS message type that can be sent between ITS edge contracts and the ITS Hub
#[cw_serde]
#[derive(Eq)]
pub enum ItsHubMessage {
    /// ITS edge source contract -> ITS Hub
    SendToHub {
        /// True destination chain of the ITS message
        destination_chain: ChainName,
        message: ItsMessage,
    },
    /// ITS Hub -> ITS edge destination contract
    ReceiveFromHub {
        /// True source chain of the ITS message
        source_chain: ChainName,
        message: ItsMessage,
    },
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
