use axelar_wasm_std::MajorityThreshold;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{HexBinary, Uint64};
use multisig::key::PublicKey;
use msgs_derive::EnsurePermissions;
use router_api::{ChainName, CrossChainId};
use xrpl_types::types::{TxHash, XRPLAccountId, XRPLToken, xrpl_account_id_string};

use crate::state::MultisigSession;

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
    /// Threshold of weighted signatures required for signing to be considered complete
    pub signing_threshold: MajorityThreshold,
    /// Name of service in the service registry for which verifiers are registered.
    pub service_name: String,
    /// Name of chain for which this prover contract creates proofs.
    pub chain_name: ChainName,
    /// Chain name of the XRPL EVM Sidechain.
    pub xrpl_evm_sidechain_chain_name: ChainName,
    /// Maximum tolerable difference between currently active verifier set and registered verifier set.
    /// The verifier set registered in the service registry must be different by more than this number
    /// of verifiers before calling UpdateVerifierSet. For example, if this is set to 1, UpdateVerifierSet
    /// will fail unless the registered verifier set and active verifier set differ by more than 1.
    pub verifier_set_diff_threshold: u32,
    /// TODO
    #[serde(with = "xrpl_account_id_string")]
    #[schemars(with = "String")] // necessary attribute in conjunction with #[serde(with ...)]
    pub xrpl_multisig_address: XRPLAccountId,
    /// TODO
    pub xrpl_fee: u64,
    /// TODO
    pub ticket_count_threshold: u32,
    /// TODO
    pub available_tickets: Vec<u32>,
    /// TODO
    pub next_sequence_number: u32,
    /// TODO
    pub last_assigned_ticket_number: u32,
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(ProofResponse)]
    Proof { multisig_session_id: Uint64 },

    #[returns(bool)]
    VerifySignature {
        signature: HexBinary,
        message: HexBinary,
        public_key: HexBinary,
        signer_address: String,
        session_id: Uint64,
    },

    #[returns(Option<multisig::verifier_set::VerifierSet>)]
    CurrentVerifierSet,

    #[returns(Option<multisig::verifier_set::VerifierSet>)]
    NextVerifierSet,

    #[returns(Option<MultisigSession>)]
    MultisigSession { message_id: CrossChainId },
}

#[cw_serde]
#[serde(tag = "status")]
pub enum ProofResponse {
    Completed {
        unsigned_tx_hash: TxHash,
        tx_blob: HexBinary,
    },
    Pending {
        unsigned_tx_hash: TxHash,
    },
}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    // Start building a proof that includes a specified message
    // Queries the gateway for actual message contents
    #[permission(Any)]
    ConstructProof {
        message_id: CrossChainId,
        payload: HexBinary,
    },

    #[permission(Elevated)]
    UpdateVerifierSet,

    #[permission(Any)]
    UpdateTxStatus { // TODO: rename to ConfirmTxStatus
        multisig_session_id: Uint64,
        signer_public_keys: Vec<PublicKey>,
        tx_id: TxHash,
    },

    #[permission(Any)]
    TicketCreate,

    #[permission(Admin)]
    TrustSet {
        xrpl_token: XRPLToken,
    },

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
pub struct MigrateMsg {
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
    /// Threshold of weighted signatures required for signing to be considered complete
    pub signing_threshold: MajorityThreshold,
    /// Name of service in the service registry for which verifiers are registered.
    pub service_name: String,
    /// Name of chain for which this prover contract creates proofs.
    pub chain_name: String,
    /// Chain name of the XRPL EVM Sidechain.
    pub xrpl_evm_sidechain_chain_name: String,
    /// Maximum tolerable difference between currently active verifier set and registered verifier set.
    /// The verifier set registered in the service registry must be different by more than this number
    /// of verifiers before calling UpdateVerifierSet. For example, if this is set to 1, UpdateVerifierSet
    /// will fail unless the registered verifier set and active verifier set differ by more than 1.
    pub verifier_set_diff_threshold: u32,
    /// TODO
    #[serde(with = "xrpl_account_id_string")]
    #[schemars(with = "String")] // necessary attribute in conjunction with #[serde(with ...)]
    pub xrpl_multisig_address: XRPLAccountId,
    /// TODO
    pub xrpl_fee: u64,
    /// TODO
    pub ticket_count_threshold: u32,
    /// TODO
    pub available_tickets: Vec<u32>,
    /// TODO
    pub next_sequence_number: u32,
    /// TODO
    pub last_assigned_ticket_number: u32,
}
