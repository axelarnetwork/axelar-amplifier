use aleo_network_config::network::NetworkConfig;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint64};
use signature_verifier_api::msg::{ExecuteMsg, QueryMsg};

#[cw_serde]
pub struct InstantiateMsg {
    pub network: NetworkConfig,
}

pub type MigrateMsg = InstantiateMsg;

pub struct Msg {
    pub signature: HexBinary,
    pub message: HexBinary,
    pub public_key: HexBinary,
    pub signer_address: String,
    pub session_id: Uint64,
}

impl From<QueryMsg> for Msg {
    fn from(msg: QueryMsg) -> Self {
        match msg {
            QueryMsg::VerifySignature {
                signature,
                message,
                public_key,
                signer_address,
                session_id,
            } => Msg {
                signature,
                message,
                public_key,
                signer_address,
                session_id,
            },
        }
    }
}

impl From<ExecuteMsg> for Msg {
    fn from(msg: ExecuteMsg) -> Self {
        match msg {
            ExecuteMsg::VerifySignature {
                signature,
                message,
                public_key,
                signer_address,
                session_id,
            } => Msg {
                signature,
                message,
                public_key,
                signer_address,
                session_id,
            },
        }
    }
}
