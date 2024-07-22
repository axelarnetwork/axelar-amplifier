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
    NativeInterchainToken = 0,
    MintBurnFrom = 1,
    LockUnlock = 2,
    LockUnlockFee = 3,
    MintBurn = 4,
    Gateway = 5,
}

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

#[cw_serde]
#[derive(Eq)]
pub struct ItsRoutedMessage {
    /// Remote chain name.
    /// ITS edge source contract -> ITS Hub GMP call: Set to the true destination chain name.
    /// ITS Hub -> ITS edge destination contract: Set to the true source chain name.
    pub remote_chain: ChainName,
    pub message: ItsMessage,
}

impl TokenId {
    pub fn new(id: [u8; 32]) -> Self {
        id.into()
    }
}

impl From<[u8; 32]> for TokenId {
    fn from(id: [u8; 32]) -> Self {
        Self(id)
    }
}

impl From<TokenId> for [u8; 32] {
    fn from(id: TokenId) -> Self {
        id.0
    }
}
