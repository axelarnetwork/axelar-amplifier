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
    // governance modifies the addresses in the allowed caller list.
    pub governance_address: String,
}

#[cw_serde]
pub enum ExecuteMsg {
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
    AuthorizeCaller {
        // Adds an address to AUTHORIZED_CALLERS, representing the addresses that can start a signing session.
        contract_address: Addr,
    },
    UnauthorizeCaller {
        // Removes an address from AUTHORIZED_CALLERS
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
