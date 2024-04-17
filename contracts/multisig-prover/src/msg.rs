use axelar_wasm_std::MajorityThreshold;
use connection_router_api::CrossChainId;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{HexBinary, Uint256, Uint64};
use multisig::key::KeyType;

use crate::encoding::{Data, Encoder};

#[cw_serde]
pub struct InstantiateMsg {
    // Address that can call UpdateWorkerSet
    pub admin_address: String,
    // Address that can call UpdateSigning threshold, as well as automatically confirm worker set updates, bypassing verification
    pub governance_address: String,
    // Address of the gateway on axelar associated with the destination chain. For example, if this prover is creating proofs to
    // be relayed to Ethereum, this is the address of the gateway on Axelar for Ethereum.
    pub gateway_address: String,
    // Address of the multisig contract on axelar.
    pub multisig_address: String,
    // Address of the monitoring contract on axelar.
    pub monitoring_address: String,
    // Address of the service registry contract on axelar.
    pub service_registry_address: String,
    // Address of the voting verifier contract on axelar associated with the destination chain. For example, if this prover is creating
    // proofs to be relayed to Ethereum, this is the address of the voting verifier for Ethereum.
    pub voting_verifier_address: String,
    // Chain id of the chain for which this prover contract creates proofs. For example, if the destination chain is Ethereum, the chain id is 1.
    pub destination_chain_id: Uint256,
    // Threshold of weighted signatures required for signing to be considered complete
    pub signing_threshold: MajorityThreshold,
    // Name of service in the service registry for which verifiers are registered.
    pub service_name: String,
    // Name of chain for which this prover contract creates proofs.
    pub chain_name: String,
    // Maximum tolerable difference between currently active workerset and registered workerset.
    // The workerset registered in the service registry must be different by more than this number
    // of workers before calling UpdateWorkerSet. For example, if this is set to 1, UpdateWorkerSet
    // will fail unless the registered workerset and active workerset differ by more than 1.
    pub worker_set_diff_threshold: u32,
    // Type of encoding to use for signed batches.
    pub encoder: Encoder,
    // Key type to use for signing.
    pub key_type: KeyType,
}

#[cw_serde]
pub enum ExecuteMsg {
    // Start building a proof that includes specified messages
    // Queries the gateway for actual message contents
    ConstructProof {
        message_ids: Vec<CrossChainId>,
    },
    UpdateWorkerSet,
    ConfirmWorkerSet,
    // Updates the signing threshold. The threshold currently in use does not change.
    // The worker set must be updated and confirmed for the change to take effect.
    // Callable only by governance.
    UpdateSigningThreshold {
        new_signing_threshold: MajorityThreshold,
    },
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
pub struct MigrateMsg {
    pub governance_address: String,
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
