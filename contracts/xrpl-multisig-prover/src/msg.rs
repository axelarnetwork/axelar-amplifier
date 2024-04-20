use connection_router_api::CrossChainId;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{HexBinary, Uint64};
use axelar_wasm_std::{MajorityThreshold, VerificationStatus};
use multisig::key::{PublicKey, Signature};

use crate::types::{TxHash, XRPLToken};

#[cw_serde]
pub struct InstantiateMsg {
    pub admin_address: String,
    pub axelar_multisig_address: String,
    pub gateway_address: String,
    pub signing_threshold: MajorityThreshold,
    pub xrpl_multisig_address: String,
    pub voting_verifier_address: String,
    pub service_registry_address: String,
    pub monitoring_address: String,
    pub service_name: String,
    pub worker_set_diff_threshold: u32,
    pub xrpl_fee: u64,
    pub ticket_count_threshold: u32,
    pub available_tickets: Vec<u32>,
    pub next_sequence_number: u32,
    pub last_assigned_ticket_number: u32,
    pub governance_address: String,
    pub relayer_address: String, // TODO: REMOVE
    pub xrp_denom: String,
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(GetProofResponse)]
    GetProof { multisig_session_id: Uint64 },

    #[returns(bool)]
    VerifySignature {
        signature: HexBinary,
        message: HexBinary,
        public_key: HexBinary,
        signer_address: String,
        session_id: Uint64,
    },

    #[returns(multisig::worker_set::WorkerSet)]
    GetWorkerSet,

    #[returns(Option<u64>)]
    GetMultisigSessionId { message_id: CrossChainId },
}

#[cw_serde]
#[serde(tag = "status")]
pub enum GetProofResponse {
    Completed { unsigned_tx_hash: TxHash, tx_blob: HexBinary},
    Pending { unsigned_tx_hash: TxHash },
}

#[cw_serde]
pub enum ExecuteMsg {
    RegisterToken { denom: String, token: XRPLToken, decimals: u8 },
    // TODO: remove coin parameter
    ConstructProof { message_id: CrossChainId, coin: cosmwasm_std::Coin },
    UpdateTxStatus {
        multisig_session_id: Uint64,
        signer_public_keys: Vec<PublicKey>,
        message_id: CrossChainId,
        message_status: VerificationStatus,
    },
    UpdateWorkerSet,
    TicketCreate,
    UpdateSigningThreshold {
        new_signing_threshold: MajorityThreshold,
    },
}

#[cw_serde]
pub struct MigrateMsg {
    pub governance_address: String,
}
