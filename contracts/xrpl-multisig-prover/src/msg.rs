use connection_router::{state::CrossChainId, Message};
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{HexBinary, Uint64, Addr};
use axelar_wasm_std::VerificationStatus;

use crate::types::{TxHash, XRPLToken};

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(GetProofResponse)]
    GetProof { multisig_session_id: Uint64 },

    #[returns(GetMessageToSignResponse)]
    GetMessageToSign { multisig_session_id: Uint64, signer_xrpl_address: String },

    #[returns(multisig::worker_set::WorkerSet)]
    GetWorkerSet,
}

#[cw_serde]
#[serde(tag = "status")]
pub enum GetProofResponse {
    Completed { unsigned_tx_hash: TxHash, tx_blob: HexBinary},
    Pending { unsigned_tx_hash: TxHash },
}

#[cw_serde]
pub struct GetMessageToSignResponse {
    pub tx_hash: HexBinary,
}

#[cw_serde]
pub enum ExecuteMsg {
    RegisterToken { denom: String, token: XRPLToken },
    ConstructProof { message_id: CrossChainId },
    UpdateTxStatus {
        multisig_session_id: Uint64,
        signers: Vec<Addr>,
        message_id: CrossChainId,
        message_status: VerificationStatus,
    },
    UpdateWorkerSet,
    TicketCreate,
}
