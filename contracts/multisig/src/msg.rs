use connection_router::state::ChainName;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, HexBinary, Uint256, Uint64};

use crate::{
    key::{KeyType, PublicKey, Signature},
    types::MultisigState,
    worker_set::WorkerSet,
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
        worker_set_id: String,
        msg: HexBinary,
        chain_name: ChainName,
        /* Address of a contract responsible for signature verification.
        The multisig contract verifies each submitted signature by default.
        But some chains need custom verification beyond this, so the verification can be optionally overridden.
        If a callback address is provided, signature verification is handled by the contract at that address
        instead of the multisig contract. TODO: define interface for callback */
        sig_verifier: Option<String>,
    },
    SubmitSignature {
        session_id: Uint64,
        signature: HexBinary,
    },
    RegisterWorkerSet {
        worker_set: WorkerSet,
    },
    RegisterPublicKey {
        public_key: PublicKey,
    },
    // Authorizes a contract to call StartSigningSession.
    AuthorizeCaller {
        contract_address: Addr,
    },
    // Unauthorizes a contract so it can no longer call StartSigningSession.
    UnauthorizeCaller {
        contract_address: Addr,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Multisig)]
    GetMultisig { session_id: Uint64 },

    #[returns(WorkerSet)]
    GetWorkerSet { worker_set_id: String },

    #[returns(PublicKey)]
    GetPublicKey {
        worker_address: String,
        key_type: KeyType,
    },
}

#[cw_serde]
#[derive(Eq, Ord, PartialOrd)]
pub struct Signer {
    pub address: Addr,
    pub weight: Uint256,
    pub pub_key: PublicKey,
}

#[cw_serde]
pub struct Multisig {
    pub state: MultisigState,
    pub quorum: Uint256,
    pub signers: Vec<(Signer, Option<Signature>)>,
}
