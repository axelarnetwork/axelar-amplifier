use cosmwasm_schema::cw_serde;

pub use chain_codec_api::msg::{ExecuteMsg, QueryMsg};

#[cw_serde]
pub struct InstantiateMsg {
    #[serde(flatten)]
    pub base: chain_codec_api::msg::InstantiateMsg,

    /// Our implementation uses this additional field to differentiate between the different chain types,
    /// but other chain-codec implementations may not need it. If you are forking this contract to implement a new chain integration,
    /// you can remove this field and the existing encoding logic.
    pub chain_type: ChainType,
}

#[cw_serde]
pub enum ChainType {
    Evm,
    Sui,
    Stellar,
}