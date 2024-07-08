use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, HexBinary, Uint128, Uint64};
use router_api::ChainName;

use crate::{
    key::{KeyType, PublicKey, Signature},
    multisig::Multisig,
    verifier_set::VerifierSet,
};

#[cw_serde]
pub struct InstantiateMsg {
    // the governance address is allowed to modify the authorized caller list for this contract
    pub governance_address: String,
    pub rewards_address: String,
    pub block_expiry: u64,
}

#[cw_serde]
pub enum ExecuteMsg {
    // Can only be called by an authorized contract.
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
    SubmitSignature {
        session_id: Uint64,
        signature: HexBinary,
    },
    RegisterVerifierSet {
        verifier_set: VerifierSet,
    },
    RegisterPublicKey {
        public_key: PublicKey,
        /* To prevent anyone from registering a public key that belongs to someone else, we require the sender
        to sign their own address using the private key */
        signed_sender_address: HexBinary,
    },
    // Authorizes a contract to call StartSigningSession. Callable only by governance
    AuthorizeCallers {
        contracts: Vec<String>,
    },
    // Unauthorizes a contract, so it can no longer call StartSigningSession. Callable only by governance
    UnauthorizeCallers {
        contracts: Vec<String>,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Multisig)]
    GetMultisig { session_id: Uint64 },

    #[returns(VerifierSet)]
    GetVerifierSet { verifier_set_id: String },

    #[returns(PublicKey)]
    GetPublicKey {
        verifier_address: String,
        key_type: KeyType,
    },

    #[returns(bool)]
    IsCallerAuthorized { contract_address: String },
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
