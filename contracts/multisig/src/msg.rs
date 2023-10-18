use std::collections::HashMap;

use axelar_wasm_std::Snapshot;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, HexBinary, Uint256, Uint64};

use crate::{
    key::{KeyType, PublicKey, Signature},
    types::{KeyID, MultisigState},
};

#[cw_serde]
pub struct InstantiateMsg {
    // the governance address is allowed to modify the authorized caller list for this contract
    pub governance_address: String,
    pub rewards_address: String,
    pub grace_period: u64, // in blocks after session has been completed
}

#[cw_serde]
pub enum ExecuteMsg {
    // Can only be called by an authorized contract.
    StartSigningSession {
        key_id: String,
        msg: HexBinary,
    },
    SubmitSignature {
        session_id: Uint64,
        signature: HexBinary,
    },
    KeyGen {
        key_id: String,
        snapshot: Snapshot,
        pub_keys_by_address: HashMap<String, (KeyType, HexBinary)>,
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

    #[returns(crate::types::Key)]
    GetKey { key_id: KeyID },

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
