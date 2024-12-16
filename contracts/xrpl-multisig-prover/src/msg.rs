use axelar_wasm_std::MajorityThreshold;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{HexBinary, Uint64};
use interchain_token_service::TokenId;
use multisig::key::PublicKey;
use msgs_derive::EnsurePermissions;
use router_api::{ChainName, ChainNameRaw, CrossChainId};
use xrpl_types::types::{tx_hash_hex, xrpl_account_id_string, TxHash, XRPLAccountId, XRPLPaymentAmount, XRPLToken};

use crate::state::MultisigSession;

#[cw_serde]
pub struct InstantiateMsg {
    /// Address that can execute all messages that either have unrestricted or admin permission level.
    /// Should be set to a trusted address that can react to unexpected interruptions to the contract's operation.
    pub admin_address: String,
    /// Address that can call all messages of unrestricted, admin and governance permission level.
    /// This address can execute messages that bypasses verification checks to rescue the contract if it got into an otherwise unrecoverable state due to external forces.
    /// On mainnet, it should match the address of the Cosmos governance module.
    pub governance_address: String,
    /// Address of the XRPL gateway on axelar.
    pub gateway_address: String,
    /// Address of the multisig contract on axelar.
    pub multisig_address: String,
    /// Address of the coordinator contract on axelar.
    pub coordinator_address: String,
    /// Address of the service registry contract on axelar.
    pub service_registry_address: String,
    /// Address of the XRPL voting verifier contract on axelar.
    pub voting_verifier_address: String,
    /// Threshold of weighted signatures required for signing to be considered complete
    pub signing_threshold: MajorityThreshold,
    /// Name of service in the service registry for which verifiers are registered.
    pub service_name: String,
    /// Name of the XRPL chain for which this prover contract creates proofs.
    pub chain_name: ChainName,
    /// Maximum tolerable difference between currently active verifier set and registered verifier set.
    /// The verifier set registered in the service registry must be different by more than this number
    /// of verifiers before calling UpdateVerifierSet. For example, if this is set to 1, UpdateVerifierSet
    /// will fail unless the registered verifier set and active verifier set differ by more than 1.
    pub verifier_set_diff_threshold: u32,
    /// Address of the multisig account on XRPL.
    #[serde(with = "xrpl_account_id_string")]
    #[schemars(with = "String")]
    pub xrpl_multisig_address: XRPLAccountId,
    /// Fixed fee to be set in XRPL multisig transactions.
    pub xrpl_fee: u64,
    /// Number of available XRPL multisig tickets below which new tickets can be issued.
    pub ticket_count_threshold: u32,
    /// List of initial available tickets that can be used in new XRPL multisig transactions.
    pub available_tickets: Vec<u32>,
    /// Next sequence number to be used in sequential XRPL multisig transactions.
    pub next_sequence_number: u32,
    /// The ticket number that was last assigned to the XRPL multisig account.
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
    MultisigSession { cc_id: CrossChainId },
}

#[cw_serde]
#[serde(tag = "status")]
pub enum ProofResponse {
    Completed {
        #[serde(with = "tx_hash_hex")]
        #[schemars(with = "String")]
        unsigned_tx_hash: TxHash,
        tx_blob: HexBinary,
    },
    Pending {
        #[serde(with = "tx_hash_hex")]
        #[schemars(with = "String")]
        unsigned_tx_hash: TxHash,
    },
}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    // Start building a proof that includes a specified message.
    // Queries the gateway for actual message contents.
    #[permission(Any)]
    ConstructProof {
        cc_id: CrossChainId,
        payload: HexBinary,
    },

    #[permission(Elevated)]
    UpdateVerifierSet,

    #[permission(Any)]
    ConfirmTxStatus {
        multisig_session_id: Uint64,
        signer_public_keys: Vec<PublicKey>,
        #[serde(with = "tx_hash_hex")]
        #[schemars(with = "String")]
        tx_id: TxHash,
    },

    #[permission(Any)]
    TicketCreate,

    #[permission(Elevated)]
    TrustSet {
        xrpl_token: XRPLToken,
    },

    #[permission(Elevated)]
    ClaimDust {
        #[serde(with = "xrpl_account_id_string")]
        #[schemars(with = "String")]
        destination_address: XRPLAccountId,
        token_id: TokenId,
        chain: ChainNameRaw,
    },

    // Updates the signing threshold. The threshold currently in use does not change.
    // The verifier set must be updated and confirmed for the change to take effect.
    #[permission(Governance)]
    UpdateSigningThreshold {
        new_signing_threshold: MajorityThreshold,
    },

    #[permission(Elevated)]
    UpdateXrplFee {
        new_xrpl_fee: u64,
    },

    #[permission(Governance)]
    UpdateAdmin { new_admin_address: String },

    #[permission(Specific(gateway))]
    AcquireLocalDust {
        token_id: TokenId,
        dust: XRPLPaymentAmount,
    },
}

#[cw_serde]
pub struct MigrateMsg {
    /// Address that can execute all messages that either have unrestricted or admin permission level.
    /// Should be set to a trusted address that can react to unexpected interruptions to the contract's operation.
    pub admin_address: String,
    /// Address that can call all messages of unrestricted, admin and governance permission level.
    /// This address can execute messages that bypasses verification checks to rescue the contract if it got into an otherwise unrecoverable state due to external forces.
    /// On mainnet, it should match the address of the Cosmos governance module.
    pub governance_address: String,
    /// Address of the XRPL gateway on axelar.
    pub gateway_address: String,
    /// Address of the multisig contract on axelar.
    pub multisig_address: String,
    /// Address of the coordinator contract on axelar.
    pub coordinator_address: String,
    /// Address of the service registry contract on axelar.
    pub service_registry_address: String,
    /// Address of the XRPL voting verifier contract on axelar.
    pub voting_verifier_address: String,
    /// Threshold of weighted signatures required for signing to be considered complete
    pub signing_threshold: MajorityThreshold,
    /// Name of service in the service registry for which verifiers are registered.
    pub service_name: String,
    /// Name of the XRPL chain for which this prover contract creates proofs.
    pub chain_name: ChainName,
    /// Maximum tolerable difference between currently active verifier set and registered verifier set.
    /// The verifier set registered in the service registry must be different by more than this number
    /// of verifiers before calling UpdateVerifierSet. For example, if this is set to 1, UpdateVerifierSet
    /// will fail unless the registered verifier set and active verifier set differ by more than 1.
    pub verifier_set_diff_threshold: u32,
    /// Address of the multisig account on XRPL.
    #[serde(with = "xrpl_account_id_string")]
    #[schemars(with = "String")]
    pub xrpl_multisig_address: XRPLAccountId,
    /// Fixed fee to be set in XRPL multisig transactions.
    pub xrpl_fee: u64,
    /// Number of available XRPL multisig tickets below which new tickets can be issued.
    pub ticket_count_threshold: u32,
    /// List of initial available tickets that can be used in new XRPL multisig transactions.
    pub available_tickets: Vec<u32>,
    /// Next sequence number to be used in sequential XRPL multisig transactions.
    pub next_sequence_number: u32,
    /// The ticket number that was last assigned to the XRPL multisig account.
    pub last_assigned_ticket_number: u32,
}
