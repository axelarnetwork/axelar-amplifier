use connection_router::state::CrossChainId;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{HexBinary, Uint64};
use axelar_wasm_std::VerificationStatus;
use multisig::key::{PublicKey, Signature};

use crate::types::{TxHash, XRPLToken};

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(GetProofResponse)]
    GetProof { multisig_session_id: Uint64 },

    #[returns(bool)]
    VerifyMessage { multisig_session_id: Uint64, public_key: PublicKey, signature: Signature },

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
}
