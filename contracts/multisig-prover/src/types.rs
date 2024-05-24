use axelar_wasm_std::{Participant, Snapshot};
use multisig::key::PublicKey;

pub struct WorkersInfo {
    pub snapshot: Snapshot,
    pub pubkeys_by_participant: Vec<(Participant, PublicKey)>,
}
