use std::collections::HashMap;

use axelar_wasm_std::nonempty;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, HexBinary, Uint128, Uint64};
use msgs_derive::EnsurePermissions;
use router_api::ChainName;

use crate::key::{KeyType, PublicKey, Signature};
use crate::multisig::Multisig;
use crate::verifier_set::VerifierSet;

#[cw_serde]
pub struct MigrationMsg {
    pub admin_address: String,
    pub authorized_callers: HashMap<String, ChainName>,
}

#[cw_serde]
pub struct InstantiateMsg {
    /// the governance address is allowed to modify the authorized caller list for this contract
    pub governance_address: String,
    /// The admin address (or governance) is allowed to disable signing and enable signing
    pub admin_address: String,
    pub rewards_address: String,
    /// number of blocks after which a signing session expires
    pub block_expiry: nonempty::Uint64,
}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    /// Can only be called by an authorized contract.
    #[permission(Specific(authorized))]
    StartSigningSession {
        verifier_set_id: String,
        msg: HexBinary,
        chain_name: ChainName,
        /// Address of a contract responsible for signature verification.
        /// The multisig contract verifies each submitted signature by default.
        /// But some chains need custom verification beyond this, so the verification can be optionally overridden.
        /// If a callback address is provided, signature verification is handled by the contract at that address
        /// instead of the multisig contract. Signature verifier contracts must implement interface defined in
        /// [signature_verifier_api::msg]
        sig_verifier: Option<String>,
    },
    #[permission(Any)]
    SubmitSignature {
        session_id: Uint64,
        signature: HexBinary,
    },
    #[permission(Any)]
    RegisterVerifierSet { verifier_set: VerifierSet },
    #[permission(Any)]
    RegisterPublicKey {
        public_key: PublicKey,
        /// To prevent anyone from registering a public key that belongs to someone else, we require the sender
        /// to sign their own address using the private key
        signed_sender_address: HexBinary,
    },
    /// Authorizes a set of contracts to call StartSigningSession.
    #[permission(Governance)]
    AuthorizeCallers {
        contracts: HashMap<String, ChainName>,
    },
    /// Unauthorizes a set of contracts, so they can no longer call StartSigningSession.
    #[permission(Elevated)]
    UnauthorizeCallers {
        contracts: HashMap<String, ChainName>,
    },

    /// Emergency command to stop all amplifier signing
    #[permission(Elevated)]
    DisableSigning,

    /// Resumes routing after an emergency shutdown
    #[permission(Elevated)]
    EnableSigning,
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Multisig)]
    Multisig { session_id: Uint64 },

    #[returns(VerifierSet)]
    VerifierSet { verifier_set_id: String },

    #[returns(PublicKey)]
    PublicKey {
        verifier_address: String,
        key_type: KeyType,
    },

    #[returns(bool)]
    IsCallerAuthorized {
        contract_address: String,
        chain_name: ChainName,
    },
}

#[cw_serde]
#[derive(Eq, Ord, PartialOrd)]
pub struct Signer {
    pub address: Addr,
    pub weight: Uint128,
    pub pub_key: PublicKey,
}

impl Signer {
    pub fn with_sig(&self, signature: Signature) -> SignerWithSig {
        SignerWithSig {
            signer: self.clone(),
            signature,
        }
    }
}

#[cw_serde]
pub struct SignerWithSig {
    pub signer: Signer,
    pub signature: Signature,
}
