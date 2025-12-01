use axelar_wasm_std::MajorityThreshold;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{HexBinary, Uint64};
use msgs_derive::Permissions;
use router_api::CrossChainId;
pub use solana_multisig_prover_api::msg::InstantiateMsg;

pub use crate::contract::MigrateMsg;
use crate::Payload;

#[cw_serde]
#[derive(Permissions)]
pub enum ExecuteMsg {
    // Start building a proof that includes specified messages
    // Queries the gateway for actual message contents
    #[permission(Any)]
    ConstructProof(Vec<CrossChainId>),
    #[permission(Elevated)]
    UpdateVerifierSet,

    #[permission(Any)]
    ConfirmVerifierSet,
    // Updates the signing threshold. The threshold currently in use does not change.
    // The verifier set must be updated and confirmed for the change to take effect.
    #[permission(Governance)]
    UpdateSigningThreshold {
        new_signing_threshold: MajorityThreshold,
    },
    #[permission(Governance)]
    UpdateAdmin { new_admin_address: String },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(ProofResponse)]
    Proof { multisig_session_id: Uint64 },

    /// Returns a `VerifierSetResponse` with the current verifier set id and the verifier set itself.
    #[returns(Option<VerifierSetResponse>)]
    CurrentVerifierSet,

    /// Returns a `VerifierSetResponse` with the next verifier set id and the verifier set itself.
    #[returns(Option<VerifierSetResponse>)]
    NextVerifierSet,
}

#[cw_serde]
pub enum ProofStatus {
    Pending,
    Completed { execute_data: HexBinary }, // encoded data and proof sent to destination gateway
}

#[cw_serde]
pub struct ProofResponse {
    pub multisig_session_id: Uint64,
    pub message_ids: Vec<CrossChainId>,
    pub payload: Payload,
    pub status: ProofStatus,
}

#[cw_serde]
pub struct VerifierSetResponse {
    pub id: String,
    pub verifier_set: multisig::verifier_set::VerifierSet,
}

impl From<multisig::verifier_set::VerifierSet> for VerifierSetResponse {
    fn from(set: multisig::verifier_set::VerifierSet) -> Self {
        VerifierSetResponse {
            id: set.id(),
            verifier_set: set,
        }
    }
}
