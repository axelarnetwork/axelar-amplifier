use std::collections::HashMap;

use cosmwasm_std::{Addr, HexBinary, Uint64};

// Emitted when a new signing session is open
pub struct SigningStarted {
    pub multisig_session_id: Uint64,
    pub key_set_id: Uint64,
    pub pub_keys: HashMap<String, HexBinary>,
    pub sig_msg: HexBinary,
}

// Emitted when a participants submits a signature
pub struct SignatureSubmitted {
    pub multisig_session_id: Uint64,
    pub participant: Addr,
    pub signature: HexBinary,
}

// Emitted when a signing session was completed
pub struct SigningCompleted {
    pub multisig_session_id: Uint64,
}
