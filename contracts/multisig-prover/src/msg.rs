use axelar_wasm_std::MajorityThreshold;
use connection_router::state::CrossChainId;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{HexBinary, Uint256, Uint64};
use multisig::key::KeyType;

use crate::encoding::{Data, Encoder};

#[cw_serde]
pub struct InstantiateMsg {
    pub admin_address: String,
    pub gateway_address: String,
    pub multisig_address: String,
    pub service_registry_address: String,
    pub voting_verifier_address: String,
    pub destination_chain_id: Uint256,
    pub signing_threshold: MajorityThreshold,
    pub service_name: String,
    pub chain_name: String,
    pub worker_set_diff_threshold: u32,
    pub encoder: Encoder,
    pub key_type: KeyType,
}

#[cw_serde]
pub enum ExecuteMsg {
    // Start building a proof that includes specified messages
    // Queries the gateway for actual message contents
    ConstructProof { message_ids: Vec<CrossChainId> },
    UpdateWorkerSet,
    ConfirmWorkerSet,
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(GetProofResponse)]
    GetProof { multisig_session_id: Uint64 },

    #[returns(multisig::worker_set::WorkerSet)]
    GetWorkerSet,
}

#[cw_serde]
pub enum ProofStatus {
    Pending,
    Completed { execute_data: HexBinary }, // encoded data and proof sent to destination gateway
}

#[cw_serde]
pub struct GetProofResponse {
    pub multisig_session_id: Uint64,
    pub message_ids: Vec<CrossChainId>,
    pub data: Data,
    pub status: ProofStatus,
}
