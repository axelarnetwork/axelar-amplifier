use axelar_wasm_std::MajorityThreshold;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{HexBinary, Uint64};
use msgs_derive::Permissions;
use multisig::key::KeyType;
use router_api::CrossChainId;

use crate::payload::Payload;

#[cw_serde]
pub struct InstantiateMsg {
    /// Address that can execute all messages that either have unrestricted or admin permission level, such as Updateverifier set.
    /// Should be set to a trusted address that can react to unexpected interruptions to the contract's operation.
    pub admin_address: String,
    /// Address that can call all messages of unrestricted, admin and governance permission level, such as UpdateSigningThreshold.
    /// This address can execute messages that bypasses verification checks to rescue the contract if it got into an otherwise unrecoverable state due to external forces.
    /// On mainnet, it should match the address of the Cosmos governance module.
    pub governance_address: String,
    /// Address of the gateway on axelar associated with the destination chain. For example, if this prover is creating proofs to
    /// be relayed to Ethereum, this is the address of the gateway on Axelar for Ethereum.
    pub gateway_address: String,
    /// Address of the multisig contract on axelar.
    pub multisig_address: String,
    /// Address of the coordinator contract on axelar.
    pub coordinator_address: String,
    /// Address of the service registry contract on axelar.
    pub service_registry_address: String,
    /// Address of the voting verifier contract on axelar associated with the destination chain. For example, if this prover is creating
    /// proofs to be relayed to Ethereum, this is the address of the voting verifier for Ethereum.
    pub voting_verifier_address: String,
    /// Address of the chain codec contract on axelar associated with the destination chain.
    /// This is the contract that encodes the execute data for the target chain that the relayer will submit.
    pub chain_codec_address: String,
    /// Threshold of weighted signatures required for signing to be considered complete
    pub signing_threshold: MajorityThreshold,
    /// Name of service in the service registry for which verifiers are registered.
    pub service_name: String,
    /// TODO: Change to ChainName
    /// Name of chain for which this prover contract creates proofs.
    pub chain_name: String,
    /// Maximum tolerable difference between currently active verifier set and registered verifier set.
    /// The verifier set registered in the service registry must be different by more than this number
    /// of verifiers before calling UpdateVerifierSet. For example, if this is set to 1, UpdateVerifierSet
    /// will fail unless the registered verifier set and active verifier set differ by more than 1.
    pub verifier_set_diff_threshold: u32,
    /// Public key type verifiers use for signing payload. Different blockchains support different cryptographic signature algorithms (ECDSA, Ed25519, etc).
    /// This defines the specific signature algorithm to use for this prover, which should correspond to the signature algorithm used by the gateway
    /// deployed on the destination chain. The multisig contract supports multiple public keys per verifier (each a different type of key), and this
    /// parameter controls which registered public key to use for signing for each verifier registered to the destination chain.
    pub key_type: KeyType,
    /// Address of a contract responsible for signature verification.
    /// For detailed information, see [`multisig::msg::ExecuteMsg::StartSigningSession::sig_verifier`]
    pub sig_verifier_address: Option<String>,
}

#[cw_serde]
#[derive(Permissions)]
pub enum ExecuteMsg {
    // Start building a proof that includes specified messages
    // Queries the gateway for actual message contents
    #[permission(Any)]
    #[cfg(not(feature = "receive-payload"))]
    ConstructProof(Vec<CrossChainId>),
    #[permission(Any)]
    #[cfg(feature = "receive-payload")]
    ConstructProof {
        message_ids: Vec<CrossChainId>,
        payload_bytes: Vec<HexBinary>,
    },

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
